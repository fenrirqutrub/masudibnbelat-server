package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"mime/multipart"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ═══════════════════════════════════════════════════════════════
// GLOBALS & TYPES
// ═══════════════════════════════════════════════════════════════
var (
	db                                  *DatabaseManager
	cld                                 *cloudinary.Cloudinary
	categoryCol, articleCol, commentCol *mongo.Collection
	rateLimiter                         *RateLimiter
	slugRegex                           = regexp.MustCompile(`[^a-z0-9]+`)
	allowedImgTypes                     = map[string]bool{"image/jpeg": true, "image/png": true, "image/gif": true, "image/webp": true}
)

type (
	DatabaseManager struct {
		client *mongo.Client
		mu     sync.RWMutex
		ok     bool
	}
	RateLimiter struct {
		reqs map[string]int
		max  int
		mu   sync.Mutex
	}
	Category struct {
		ID        primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
		Name      string             `json:"name" bson:"name"`
		Slug      string             `json:"slug" bson:"slug"`
		CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
		UpdatedAt time.Time          `json:"updatedAt" bson:"updatedAt"`
	}
	Image struct {
		URL      string `json:"url" bson:"url"`
		PublicID string `json:"publicId" bson:"publicId"`
	}
	Article struct {
		ID        primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
		Category  primitive.ObjectID `json:"category" bson:"category"`
		Title     string             `json:"title" bson:"title"`
		Desc      string             `json:"description" bson:"description"`
		Img       Image              `json:"img" bson:"img"`
		Views     int                `json:"views" bson:"views"`
		Shares    int                `json:"shares" bson:"shares"`
		CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
		UpdatedAt time.Time          `json:"updatedAt" bson:"updatedAt"`
	}
	Comment struct {
		ID        primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
		ArticleID primitive.ObjectID `json:"articleId" bson:"articleId"`
		Text      string             `json:"text" bson:"text"`
		Author    string             `json:"author" bson:"author"`
		Hash      string             `json:"userHash" bson:"userHash"`
		CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
		UpdatedAt time.Time          `json:"updatedAt" bson:"updatedAt"`
	}
	CatInfo struct {
		ID   primitive.ObjectID `json:"_id" bson:"_id"`
		Name string             `json:"name" bson:"name"`
		Slug string             `json:"slug" bson:"slug"`
	}
	ArticleRes struct {
		ID        string    `json:"_id"`
		Title     string    `json:"title"`
		Desc      string    `json:"description"`
		Img       Image     `json:"img"`
		Category  CatInfo   `json:"category"`
		Views     int       `json:"views"`
		Shares    int       `json:"shares"`
		CreatedAt time.Time `json:"createdAt"`
		TimeAgo   string    `json:"timeAgo"`
		Comments  int       `json:"comments"`
	}
)

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func ctx(s int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(s)*time.Second)
}
func objID(s string) (primitive.ObjectID, bool) {
	id, e := primitive.ObjectIDFromHex(s)
	return id, e == nil
}
func slug(s string) string {
	return strings.Trim(slugRegex.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-"), "-")
}
func hash(c *fiber.Ctx) string {
	h := sha256.Sum256([]byte(c.IP() + "|" + c.Get("User-Agent")))
	return hex.EncodeToString(h[:])
}
func fail(c *fiber.Ctx, code int, msg string) error {
	return c.Status(code).JSON(fiber.Map{"success": false, "message": msg})
}
func ok(c *fiber.Ctx, data any) error { return c.JSON(fiber.Map{"success": true, "data": data}) }

func timeAgo(t time.Time) string {
	s := int(time.Since(t).Seconds())
	for _, i := range []struct {
		l string
		s int
	}{{"year", 31536000}, {"month", 2592000}, {"day", 86400}, {"hour", 3600}, {"minute", 60}} {
		if c := s / i.s; c >= 1 {
			p := ""
			if c > 1 {
				p = "s"
			}
			return fmt.Sprintf("%d %s%s ago", c, i.l, p)
		}
	}
	return "just now"
}

// ═══════════════════════════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════════════════════════
func (d *DatabaseManager) Connect() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ok {
		return nil
	}
	c, cancel := ctx(10)
	defer cancel()
	client, err := mongo.Connect(c, options.Client().ApplyURI(env("MONGODB_URI", "")).SetMaxPoolSize(10).SetMinPoolSize(2))
	if err != nil {
		return err
	}
	if err = client.Ping(c, nil); err != nil {
		return err
	}
	d.client, d.ok = client, true
	log.Println("✅ MongoDB Connected")
	return nil
}
func (d *DatabaseManager) Healthy() bool {
	d.mu.RLock()
	cl, ok := d.client, d.ok
	d.mu.RUnlock()
	if !ok {
		return false
	}
	c, cancel := ctx(2)
	defer cancel()
	return cl.Ping(c, nil) == nil
}
func (d *DatabaseManager) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ok {
		c, cancel := ctx(5)
		defer cancel()
		d.ok = false
		return d.client.Disconnect(c)
	}
	return nil
}
func (d *DatabaseManager) DB(n string) *mongo.Database {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.client.Database(n)
}

// ═══════════════════════════════════════════════════════════════
// CLOUDINARY
// ═══════════════════════════════════════════════════════════════
func upload(f multipart.File, folder string) (*Image, error) {
	c, cancel := ctx(30)
	defer cancel()
	r, err := cld.Upload.Upload(c, f, uploader.UploadParams{Folder: folder, Transformation: "q_auto:good,f_auto"})
	if err != nil {
		return nil, err
	}
	return &Image{URL: r.SecureURL, PublicID: r.PublicID}, nil
}
func deleteImg(id string) {
	c, cancel := ctx(10)
	defer cancel()
	cld.Upload.Destroy(c, uploader.DestroyParams{PublicID: id})
}

// ═══════════════════════════════════════════════════════════════
// RATE LIMITER
// ═══════════════════════════════════════════════════════════════
func NewRL(max int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{reqs: make(map[string]int), max: max}
	go func() {
		for range time.Tick(window) {
			rl.mu.Lock()
			rl.reqs = make(map[string]int)
			rl.mu.Unlock()
		}
	}()
	return rl
}
func (r *RateLimiter) MW() fiber.Handler {
	return func(c *fiber.Ctx) error {
		k := hash(c)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.reqs[k] >= r.max {
			return fail(c, 429, "Too many requests")
		}
		r.reqs[k]++
		return c.Next()
	}
}

// ═══════════════════════════════════════════════════════════════
// HANDLERS: CATEGORY
// ═══════════════════════════════════════════════════════════════
func createCategory(c *fiber.Ctx) error {
	var in struct {
		Name string `json:"name"`
	}
	if c.BodyParser(&in) != nil {
		return fail(c, 400, "Invalid JSON")
	}
	name := strings.TrimSpace(in.Name)
	if l := len(name); l < 2 || l > 50 {
		return fail(c, 400, "Name must be 2-50 chars")
	}
	s := slug(name)
	cx, cancel := ctx(5)
	defer cancel()
	if categoryCol.FindOne(cx, bson.M{"$or": []bson.M{{"name": bson.M{"$regex": "^" + regexp.QuoteMeta(name) + "$", "$options": "i"}}, {"slug": s}}}).Err() == nil {
		return fail(c, 409, "Category exists")
	}
	cat := Category{Name: name, Slug: s, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	res, err := categoryCol.InsertOne(cx, cat)
	if err != nil {
		return fail(c, 500, "Failed to create")
	}
	cat.ID = res.InsertedID.(primitive.ObjectID)
	return c.Status(201).JSON(fiber.Map{"success": true, "data": cat})
}
func getCategories(c *fiber.Ctx) error {
	cx, cancel := ctx(5)
	defer cancel()
	cur, err := categoryCol.Find(cx, bson.M{}, options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return fail(c, 500, "Failed to fetch")
	}
	defer cur.Close(cx)
	var cats []Category
	cur.All(cx, &cats)
	if cats == nil {
		cats = []Category{}
	}
	return ok(c, cats)
}
func getCategoryBySlug(c *fiber.Ctx) error {
	cx, cancel := ctx(5)
	defer cancel()
	var cat Category
	if categoryCol.FindOne(cx, bson.M{"slug": c.Params("slug")}).Decode(&cat) != nil {
		return fail(c, 404, "Not found")
	}
	return ok(c, cat)
}
func deleteCategory(c *fiber.Ctx) error {
	id, valid := objID(c.Params("id"))
	if !valid {
		return fail(c, 400, "Invalid ID")
	}
	cx, cancel := ctx(5)
	defer cancel()
	if categoryCol.FindOne(cx, bson.M{"_id": id}).Err() != nil {
		return fail(c, 404, "Not found")
	}
	if cnt, _ := articleCol.CountDocuments(cx, bson.M{"category": id}); cnt > 0 {
		return fail(c, 409, fmt.Sprintf("%d articles using this", cnt))
	}
	categoryCol.DeleteOne(cx, bson.M{"_id": id})
	return c.JSON(fiber.Map{"success": true, "message": "Deleted"})
}

// ═══════════════════════════════════════════════════════════════
// HANDLERS: ARTICLE
// ═══════════════════════════════════════════════════════════════
func createArticle(c *fiber.Ctx) error {
	title, desc, catID := strings.TrimSpace(c.FormValue("title")), strings.TrimSpace(c.FormValue("description")), c.FormValue("categoryId")
	if l := len(title); l < 5 || l > 200 {
		return fail(c, 400, "Title 5-200 chars")
	}
	if l := len(desc); l < 20 || l > 5000 {
		return fail(c, 400, "Desc 20-5000 chars")
	}
	cid, valid := objID(catID)
	if !valid {
		return fail(c, 400, "Invalid category")
	}
	file, err := c.FormFile("img")
	if err != nil {
		return fail(c, 400, "Image required")
	}
	if file.Size > 5<<20 {
		return fail(c, 400, "Max 5MB")
	}
	if !allowedImgTypes[file.Header.Get("Content-Type")] {
		return fail(c, 400, "JPEG/PNG/GIF/WebP only")
	}
	cx, cancel := ctx(10)
	defer cancel()
	var cat Category
	if categoryCol.FindOne(cx, bson.M{"_id": cid}).Decode(&cat) != nil {
		return fail(c, 404, "Category not found")
	}
	f, _ := file.Open()
	defer f.Close()
	img, err := upload(f, "articles")
	if err != nil {
		return fail(c, 500, "Upload failed")
	}
	art := Article{Title: title, Desc: desc, Img: *img, Category: cid, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	res, err := articleCol.InsertOne(cx, art)
	if err != nil {
		deleteImg(img.PublicID)
		return fail(c, 500, "Failed")
	}
	art.ID = res.InsertedID.(primitive.ObjectID)
	return c.Status(201).JSON(fiber.Map{"success": true, "data": ArticleRes{art.ID.Hex(), art.Title, art.Desc, art.Img, CatInfo{cat.ID, cat.Name, cat.Slug}, 0, 0, art.CreatedAt, "just now", 0}})
}

func getArticles(c *fiber.Ctx) error {
	page, limit := max(c.QueryInt("page", 1), 1), min(max(c.QueryInt("limit", 10), 1), 100)
	filter := bson.M{}
	cx, cancel := ctx(10)
	defer cancel()
	if id, ok := objID(c.Query("categoryId")); ok {
		filter["category"] = id
	} else if s := c.Query("categorySlug"); s != "" {
		var cat Category
		if categoryCol.FindOne(cx, bson.M{"slug": s}).Decode(&cat) == nil {
			filter["category"] = cat.ID
		}
	}
	total, _ := articleCol.CountDocuments(cx, filter)
	pipe := mongo.Pipeline{
		{{Key: "$match", Value: filter}}, {{Key: "$sort", Value: bson.D{{Key: "createdAt", Value: -1}}}},
		{{Key: "$skip", Value: int64((page - 1) * limit)}}, {{Key: "$limit", Value: int64(limit)}},
		{{Key: "$lookup", Value: bson.M{"from": "categories", "localField": "category", "foreignField": "_id", "as": "cat"}}},
		{{Key: "$unwind", Value: "$cat"}},
		{{Key: "$lookup", Value: bson.M{"from": "comments", "localField": "_id", "foreignField": "articleId", "as": "cmts"}}},
		{{Key: "$addFields", Value: bson.M{"cmts": bson.M{"$size": "$cmts"}}}},
	}
	cur, err := articleCol.Aggregate(cx, pipe)
	if err != nil {
		return fail(c, 500, "Failed")
	}
	defer cur.Close(cx)
	var docs []bson.M
	cur.All(cx, &docs)
	res := make([]ArticleRes, len(docs))
	for i, d := range docs {
		cat := d["cat"].(bson.M)
		img := d["img"].(bson.M)
		res[i] = ArticleRes{d["_id"].(primitive.ObjectID).Hex(), d["title"].(string), d["description"].(string),
			Image{img["url"].(string), img["publicId"].(string)}, CatInfo{cat["_id"].(primitive.ObjectID), cat["name"].(string), cat["slug"].(string)},
			int(d["views"].(int32)), int(d["shares"].(int32)), d["createdAt"].(primitive.DateTime).Time(), timeAgo(d["createdAt"].(primitive.DateTime).Time()), int(d["cmts"].(int32))}
	}
	return c.JSON(fiber.Map{"success": true, "data": res, "pagination": fiber.Map{"page": page, "limit": limit, "total": total, "pages": int(math.Ceil(float64(total) / float64(limit)))}})
}

func getArticleByID(c *fiber.Ctx) error {
	id, valid := objID(c.Params("id"))
	if !valid {
		return fail(c, 400, "Invalid ID")
	}
	cx, cancel := ctx(5)
	defer cancel()
	var art Article
	if articleCol.FindOne(cx, bson.M{"_id": id}).Decode(&art) != nil {
		return fail(c, 404, "Not found")
	}
	var cat Category
	categoryCol.FindOne(cx, bson.M{"_id": art.Category}).Decode(&cat)
	cnt, _ := commentCol.CountDocuments(cx, bson.M{"articleId": id})
	return ok(c, ArticleRes{art.ID.Hex(), art.Title, art.Desc, art.Img, CatInfo{cat.ID, cat.Name, cat.Slug}, art.Views, art.Shares, art.CreatedAt, timeAgo(art.CreatedAt), int(cnt)})
}

func getArticlesByCategorySlug(c *fiber.Ctx) error {
	categorySlug := c.Params("categorySlug")
	page, limit := max(c.QueryInt("page", 1), 1), min(max(c.QueryInt("limit", 10), 1), 100)

	cx, cancel := ctx(10)
	defer cancel()

	// Find category by slug
	var cat Category
	if categoryCol.FindOne(cx, bson.M{"slug": categorySlug}).Decode(&cat) != nil {
		return fail(c, 404, "Category not found")
	}

	filter := bson.M{"category": cat.ID}
	total, _ := articleCol.CountDocuments(cx, filter)

	pipe := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		{{Key: "$sort", Value: bson.D{{Key: "createdAt", Value: -1}}}},
		{{Key: "$skip", Value: int64((page - 1) * limit)}},
		{{Key: "$limit", Value: int64(limit)}},
		{{Key: "$lookup", Value: bson.M{"from": "categories", "localField": "category", "foreignField": "_id", "as": "cat"}}},
		{{Key: "$unwind", Value: "$cat"}},
		{{Key: "$lookup", Value: bson.M{"from": "comments", "localField": "_id", "foreignField": "articleId", "as": "cmts"}}},
		{{Key: "$addFields", Value: bson.M{"cmts": bson.M{"$size": "$cmts"}}}},
	}

	cur, err := articleCol.Aggregate(cx, pipe)
	if err != nil {
		return fail(c, 500, "Failed")
	}
	defer cur.Close(cx)

	var docs []bson.M
	cur.All(cx, &docs)

	res := make([]ArticleRes, len(docs))
	for i, d := range docs {
		catData := d["cat"].(bson.M)
		img := d["img"].(bson.M)
		res[i] = ArticleRes{
			d["_id"].(primitive.ObjectID).Hex(),
			d["title"].(string),
			d["description"].(string),
			Image{img["url"].(string), img["publicId"].(string)},
			CatInfo{catData["_id"].(primitive.ObjectID), catData["name"].(string), catData["slug"].(string)},
			int(d["views"].(int32)),
			int(d["shares"].(int32)),
			d["createdAt"].(primitive.DateTime).Time(),
			timeAgo(d["createdAt"].(primitive.DateTime).Time()),
			int(d["cmts"].(int32)),
		}
	}

	return c.JSON(fiber.Map{
		"success":  true,
		"data":     res,
		"category": CatInfo{cat.ID, cat.Name, cat.Slug},
		"pagination": fiber.Map{
			"page":  page,
			"limit": limit,
			"total": total,
			"pages": int(math.Ceil(float64(total) / float64(limit))),
		},
	})
}

func getArticleByCategoryAndID(c *fiber.Ctx) error {
	categorySlug := c.Params("categorySlug")
	articleID := c.Params("articleId")

	id, valid := objID(articleID)
	if !valid {
		return fail(c, 400, "Invalid article ID")
	}

	cx, cancel := ctx(5)
	defer cancel()

	// Verify category exists
	var cat Category
	if categoryCol.FindOne(cx, bson.M{"slug": categorySlug}).Decode(&cat) != nil {
		return fail(c, 404, "Category not found")
	}

	// Find article and verify it belongs to the category
	var art Article
	if articleCol.FindOne(cx, bson.M{"_id": id, "category": cat.ID}).Decode(&art) != nil {
		return fail(c, 404, "Article not found in this category")
	}

	cnt, _ := commentCol.CountDocuments(cx, bson.M{"articleId": id})

	return ok(c, ArticleRes{
		art.ID.Hex(),
		art.Title,
		art.Desc,
		art.Img,
		CatInfo{cat.ID, cat.Name, cat.Slug},
		art.Views,
		art.Shares,
		art.CreatedAt,
		timeAgo(art.CreatedAt),
		int(cnt),
	})
}

func updateArticle(c *fiber.Ctx) error {
	id, valid := objID(c.Params("id"))
	if !valid {
		return fail(c, 400, "Invalid ID")
	}
	cx, cancel := ctx(10)
	defer cancel()
	var art Article
	if articleCol.FindOne(cx, bson.M{"_id": id}).Decode(&art) != nil {
		return fail(c, 404, "Not found")
	}
	upd := bson.M{"updatedAt": time.Now()}
	if t := strings.TrimSpace(c.FormValue("title")); t != "" {
		if l := len(t); l < 5 || l > 200 {
			return fail(c, 400, "Title 5-200")
		}
		upd["title"] = t
	}
	if d := strings.TrimSpace(c.FormValue("description")); d != "" {
		if l := len(d); l < 20 || l > 5000 {
			return fail(c, 400, "Desc 20-5000")
		}
		upd["description"] = d
	}
	if cid, ok := objID(c.FormValue("categoryId")); ok {
		if categoryCol.FindOne(cx, bson.M{"_id": cid}).Err() != nil {
			return fail(c, 404, "Category not found")
		}
		upd["category"] = cid
	}
	if file, err := c.FormFile("img"); err == nil {
		if file.Size > 5<<20 {
			return fail(c, 400, "Max 5MB")
		}
		if !allowedImgTypes[file.Header.Get("Content-Type")] {
			return fail(c, 400, "Invalid type")
		}
		f, _ := file.Open()
		defer f.Close()
		img, err := upload(f, "articles")
		if err != nil {
			return fail(c, 500, "Upload failed")
		}
		go deleteImg(art.Img.PublicID)
		upd["img"] = img
	}
	if len(upd) == 1 {
		return fail(c, 400, "No updates")
	}
	articleCol.UpdateOne(cx, bson.M{"_id": id}, bson.M{"$set": upd})
	articleCol.FindOne(cx, bson.M{"_id": id}).Decode(&art)
	var cat Category
	categoryCol.FindOne(cx, bson.M{"_id": art.Category}).Decode(&cat)
	cnt, _ := commentCol.CountDocuments(cx, bson.M{"articleId": id})
	return ok(c, ArticleRes{art.ID.Hex(), art.Title, art.Desc, art.Img, CatInfo{cat.ID, cat.Name, cat.Slug}, art.Views, art.Shares, art.CreatedAt, timeAgo(art.CreatedAt), int(cnt)})
}

func incViews(c *fiber.Ctx) error  { return incField(c, "views") }
func incShares(c *fiber.Ctx) error { return incField(c, "shares") }
func incField(c *fiber.Ctx, f string) error {
	id, valid := objID(c.Params("id"))
	if !valid {
		return fail(c, 400, "Invalid ID")
	}
	cx, cancel := ctx(5)
	defer cancel()
	var art Article
	if articleCol.FindOneAndUpdate(cx, bson.M{"_id": id}, bson.M{"$inc": bson.M{f: 1}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&art) != nil {
		return fail(c, 404, "Not found")
	}
	v := art.Views
	if f == "shares" {
		v = art.Shares
	}
	return ok(c, fiber.Map{f: v})
}

func deleteArticle(c *fiber.Ctx) error {
	id, valid := objID(c.Params("id"))
	if !valid {
		return fail(c, 400, "Invalid ID")
	}
	cx, cancel := ctx(10)
	defer cancel()
	var art Article
	if articleCol.FindOne(cx, bson.M{"_id": id}).Decode(&art) != nil {
		return fail(c, 404, "Not found")
	}
	deleteImg(art.Img.PublicID)
	commentCol.DeleteMany(cx, bson.M{"articleId": id})
	articleCol.DeleteOne(cx, bson.M{"_id": id})
	return c.JSON(fiber.Map{"success": true, "message": "Deleted"})
}

// ═══════════════════════════════════════════════════════════════
// HANDLERS: COMMENT
// ═══════════════════════════════════════════════════════════════
func getComments(c *fiber.Ctx) error {
	id, valid := objID(c.Params("id"))
	if !valid {
		return fail(c, 400, "Invalid ID")
	}
	cx, cancel := ctx(5)
	defer cancel()
	if cnt, _ := articleCol.CountDocuments(cx, bson.M{"_id": id}); cnt == 0 {
		return fail(c, 404, "Article not found")
	}
	cur, err := commentCol.Find(cx, bson.M{"articleId": id}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
	if err != nil {
		return fail(c, 500, "Failed")
	}
	defer cur.Close(cx)
	var cmts []Comment
	cur.All(cx, &cmts)
	res := make([]fiber.Map, len(cmts))
	for i, cm := range cmts {
		res[i] = fiber.Map{"_id": cm.ID, "articleId": cm.ArticleID, "text": cm.Text, "author": cm.Author, "userHash": cm.Hash, "createdAt": cm.CreatedAt, "timeAgo": timeAgo(cm.CreatedAt)}
	}
	return ok(c, res)
}

func createComment(c *fiber.Ctx) error {
	id, valid := objID(c.Params("id"))
	if !valid {
		return fail(c, 400, "Invalid ID")
	}
	cx, cancel := ctx(5)
	defer cancel()
	if cnt, _ := articleCol.CountDocuments(cx, bson.M{"_id": id}); cnt == 0 {
		return fail(c, 404, "Article not found")
	}
	var in struct{ Text, Author string }
	if c.BodyParser(&in) != nil {
		return fail(c, 400, "Invalid JSON")
	}
	text := strings.TrimSpace(in.Text)
	if l := len(text); l < 1 || l > 1000 {
		return fail(c, 400, "Text 1-1000 chars")
	}
	author := strings.TrimSpace(in.Author)
	if author == "" {
		author = "Anonymous"
	} else if len(author) > 50 {
		return fail(c, 400, "Author too long")
	}
	cmt := Comment{ArticleID: id, Text: text, Author: author, Hash: hash(c), CreatedAt: time.Now(), UpdatedAt: time.Now()}
	res, err := commentCol.InsertOne(cx, cmt)
	if err != nil {
		return fail(c, 500, "Failed")
	}
	cmt.ID = res.InsertedID.(primitive.ObjectID)
	return c.Status(201).JSON(fiber.Map{"success": true, "data": fiber.Map{"_id": cmt.ID, "articleId": cmt.ArticleID, "text": cmt.Text, "author": cmt.Author, "userHash": cmt.Hash, "createdAt": cmt.CreatedAt, "timeAgo": "just now"}})
}

// ═══════════════════════════════════════════════════════════════
// HEALTH
// ═══════════════════════════════════════════════════════════════
func healthCheck(c *fiber.Ctx) error {
	healthy := db.Healthy()
	status := 200
	if !healthy {
		status = 503
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return c.Status(status).JSON(fiber.Map{"status": map[bool]string{true: "healthy", false: "degraded"}[healthy], "database": fiber.Map{"healthy": healthy}, "memory": fiber.Map{"alloc": m.Alloc, "sys": m.Sys}})
}

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════
func main() {
	godotenv.Load()
	db = &DatabaseManager{}
	if err := db.Connect(); err != nil {
		log.Fatal("❌ DB:", err)
	}
	var err error
	cld, err = cloudinary.New()
	if err != nil {
		log.Fatal("❌ Cloudinary:", err)
	}
	database := db.DB("blogdb")
	categoryCol, articleCol, commentCol = database.Collection("categories"), database.Collection("articles"), database.Collection("comments")

	// Indexes
	cx, cancel := ctx(10)
	defer cancel()
	categoryCol.Indexes().CreateOne(cx, mongo.IndexModel{Keys: bson.D{{Key: "slug", Value: 1}}, Options: options.Index().SetUnique(true)})
	articleCol.Indexes().CreateMany(cx, []mongo.IndexModel{{Keys: bson.D{{Key: "category", Value: 1}, {Key: "createdAt", Value: -1}}}, {Keys: bson.D{{Key: "views", Value: -1}}}})
	commentCol.Indexes().CreateMany(cx, []mongo.IndexModel{{Keys: bson.D{{Key: "articleId", Value: 1}, {Key: "createdAt", Value: -1}}}, {Keys: bson.D{{Key: "userHash", Value: 1}}}})

	rateLimiter = NewRL(10, 60*time.Second)

	app := fiber.New(fiber.Config{BodyLimit: 10 << 20, ErrorHandler: func(c *fiber.Ctx, err error) error {
		code, msg := 500, "Internal error"
		if e, ok := err.(*fiber.Error); ok {
			code, msg = e.Code, e.Message
		}
		return c.Status(code).JSON(fiber.Map{"success": false, "message": msg})
	}})

	origins := env("ALLOWED_ORIGINS", "http://localhost:5173")

	app.Use(helmet.New(), compress.New(), cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowCredentials: origins != "" && origins != "*",
		AllowMethods:     "GET,POST,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
	}))

	app.Use(func(c *fiber.Ctx) error {
		if !db.Healthy() {
			if db.Connect() != nil {
				return fail(c, 503, "DB unavailable")
			}
		}
		return c.Next()
	})

	// ═══════════════════════════════════════════════════════════════
	// ROUTES
	// ═══════════════════════════════════════════════════════════════

	// Root
	app.Get("/", func(c *fiber.Ctx) error {
		return ok(c, fiber.Map{"name": "Blog API", "version": "3.0.0", "status": "operational"})
	})

	// Category routes
	app.Post("/api/categories", createCategory)
	app.Get("/api/categories", getCategories)
	app.Get("/api/categories/:slug", getCategoryBySlug)
	app.Delete("/api/categories/:id", deleteCategory)

	// Article routes (general)
	app.Post("/api/articles", createArticle)
	app.Get("/api/articles", getArticles)
	app.Get("/api/articles/:id", getArticleByID)
	app.Patch("/api/articles/:id", updateArticle)
	app.Post("/api/articles/:id/view", incViews)
	app.Post("/api/articles/:id/share", incShares)
	app.Delete("/api/articles/:id", deleteArticle)

	// Comment routes
	app.Get("/api/articles/:id/comments", getComments)
	app.Post("/api/articles/:id/comments", rateLimiter.MW(), createComment)

	// GET /api/category/:categorySlug - Get all articles in a category (e.g., /api/category/technology, /api/category/islamic)
	app.Get("/api/category/:categorySlug", getArticlesByCategorySlug)

	// GET /api/category/:categorySlug/:articleId - Get single article by category and ID
	app.Get("/api/category/:categorySlug/:articleId", getArticleByCategoryAndID)

	// Health check
	app.Get("/health", healthCheck)

	// 404 handler
	app.Use(func(c *fiber.Ctx) error { return fail(c, 404, fmt.Sprintf("%s %s not found", c.Method(), c.Path())) })

	port := env("PORT", "5000")
	go func() {
		if err := app.Listen(":" + port); err != nil {
			log.Fatal("❌ Server:", err)
		}
	}()
	log.Printf("🚀 Server on :%s\n", port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("\n🛑 Shutting down...")
	app.Shutdown()
	db.Close()
	log.Println("✅ Stopped")
}

// Helper functions for min and max
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
