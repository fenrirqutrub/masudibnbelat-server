import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import Joi from "joi";
import crypto from "crypto";

dotenv.config();
const app = express();

// ────────────────────── MONGODB CONNECTION FIX ──────────────────────
let isConnected = false;

const connectDB = async () => {
  if (isConnected) {
    console.log("Using existing MongoDB connection");
    return;
  }

  try {
    mongoose.set("strictQuery", false);
    mongoose.set("bufferCommands", false); // CRITICAL: Disable buffering

    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4, // Use IPv4
    });

    isConnected = conn.connections[0].readyState === 1;
    console.log("MongoDB Connected");
  } catch (err) {
    console.error("MongoDB Connection Error:", err.message);
    isConnected = false;
    throw err;
  }
};

// Middleware to ensure DB connection before each request
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(503).json({
      success: false,
      message: "Database connection failed. Please try again.",
    });
  }
});

// ────────────────────── CONFIG ──────────────────────
app.set("trust proxy", 1);
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    optionsSuccessStatus: 204,
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ────────────────────── FAST LOG ──────────────────────
app.use((req, _, next) => {
  const start = Date.now();
  req.on("end", () => {
    if (
      req.path.startsWith("/api") ||
      req.path.startsWith("/articles") ||
      req.path.startsWith("/article")
    ) {
      console.log(
        `${req.method} ${req.path} ${req.res?.statusCode || "?"} - ${
          Date.now() - start
        }ms`
      );
    }
  });
  next();
});

// ────────────────────── MULTER ──────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, /^image\//.test(file.mimetype)),
}).single("img");

// ────────────────────── HELPERS ──────────────────────
const uploadImg = (buf) =>
  new Promise((res, rej) =>
    cloudinary.uploader
      .upload_stream({ folder: "articles", resource_type: "auto" }, (err, r) =>
        err ? rej(err) : res(r)
      )
      .end(buf)
  );

const getUserHash = (req) =>
  crypto
    .createHash("sha256")
    .update(`${req.ip}|${req.headers["user-agent"] || ""}`)
    .digest("hex");

const timeAgo = (d) => {
  const s = (Date.now() - new Date(d)) / 1000;
  const i = [
    ["year", 31536e3],
    ["month", 2592e3],
    ["day", 86400],
    ["hour", 3600],
    ["min", 60],
  ];
  for (const [l, v] of i)
    if (s >= v) return `${Math.floor(s / v)} ${l}${s >= v * 2 ? "s" : ""} ago`;
  return "now";
};

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const validId = (id) => mongoose.Types.ObjectId.isValid(id);

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ────────────────────── MODELS ──────────────────────

// Category Model
const categorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 2,
      maxlength: 50,
    },
    slug: { type: String, unique: true, trim: true },
  },
  { timestamps: true, collection: "categories" }
);

categorySchema.pre("save", function (next) {
  if (this.isModified("name")) {
    this.slug = this.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "");
  }
  next();
});

const Category =
  mongoose.models.Category || mongoose.model("Category", categorySchema);

// Unified Article Model
const articleSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, minlength: 5 },
    description: { type: String, required: true, trim: true, minlength: 20 },
    img: {
      url: { type: String, required: true },
      publicId: { type: String, required: true },
    },
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      required: true,
    },
    categorySlug: { type: String, required: true },
    views: { type: Number, default: 0 },
  },
  { timestamps: true, collection: "articles" }
);

articleSchema.index({ categorySlug: 1 });

const Article =
  mongoose.models.Article || mongoose.model("Article", articleSchema);

// Comment Model
const commentSchema = new mongoose.Schema(
  {
    articleId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "Article",
    },
    text: { type: String, required: true, trim: true, maxlength: 1000 },
    author: { type: String, default: "Anonymous" },
    userHash: { type: String, required: true },
  },
  { timestamps: true }
);

commentSchema.index({ articleId: 1 });

const Comment =
  mongoose.models.Comment || mongoose.model("Comment", commentSchema);

// ────────────────────── CATEGORY ROUTES ──────────────────────
app.post(
  "/api/category",
  asyncHandler(async (req, res) => {
    const { error, value } = Joi.object({
      categoryName: Joi.string()
        .min(2)
        .max(50)
        .required()
        .trim()
        .regex(/^[\p{L}\p{N}\s-]+$/u)
        .messages({
          "string.pattern.base": "Only letters, numbers, spaces, hyphens",
        }),
    }).validate(req.body);

    if (error)
      return res
        .status(400)
        .json({ success: false, message: error.details[0].message });

    const name = value.categoryName.trim();
    const slug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "");

    const existing = await Category.findOne({
      $or: [
        { name: { $regex: `^${escapeRegExp(name)}$`, $options: "i" } },
        { slug },
      ],
    });

    if (existing)
      return res
        .status(400)
        .json({ success: false, message: "Category already exists" });

    const category = await Category.create({ name, slug });
    res.status(201).json({ success: true, data: category });
  })
);

app.get(
  "/api/category",
  asyncHandler(async (req, res) => {
    const categories = await Category.find()
      .select("name slug createdAt")
      .sort({ createdAt: -1 });
    res.json({ success: true, data: categories });
  })
);

app.delete(
  "/api/category/:id",
  asyncHandler(async (req, res) => {
    const category = await Category.findById(req.params.id);
    if (!category)
      return res.status(404).json({ success: false, message: "Not found" });

    const hasArticles = await Article.exists({ category: category._id });
    if (hasArticles)
      return res
        .status(400)
        .json({ success: false, message: "Cannot delete: contains articles" });

    await Category.deleteOne({ _id: category._id });
    res.json({ success: true, message: "Category deleted" });
  })
);

// ────────────────────── PHOTOGRAPHY ROUTES ──────────────────────

// POST: Upload photo to photography category
app.post(
  "/api/photography",
  upload,
  asyncHandler(async (req, res) => {
    // Find or create photography category
    let category = await Category.findOne({ slug: "photography" });
    if (!category) {
      category = await Category.create({
        name: "Photography",
        slug: "photography",
      });
    }

    if (!req.file) {
      return res
        .status(400)
        .json({ success: false, message: "Image required" });
    }

    const { secure_url, public_id } = await uploadImg(req.file.buffer);
    const article = await Article.create({
      title: "Photography Image",
      description: "A beautiful photography moment captured in this image.",
      img: { url: secure_url, publicId: public_id },
      category: category._id,
      categorySlug: "photography",
    });

    res.status(201).json({ success: true, data: article });
  })
);

// GET: All photos with pagination
app.get(
  "/api/photography",
  asyncHandler(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;

    const photos = await Article.find({ categorySlug: "photography" })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .select("img views createdAt")
      .lean();

    const total = await Article.countDocuments({ categorySlug: "photography" });

    res.json({
      success: true,
      data: photos.map((p) => ({
        _id: p._id.toString(),
        img: p.img,
        views: p.views,
        createdAt: p.createdAt,
        timeAgo: timeAgo(p.createdAt),
      })),
      pagination: {
        page,
        total,
        pages: Math.ceil(total / limit),
        hasMore: page * limit < total,
      },
    });
  })
);

// POST: Increment view count
app.post(
  "/api/photography/:id/view",
  asyncHandler(async (req, res) => {
    if (!validId(req.params.id)) {
      return res.status(400).json({ success: false, message: "Invalid ID" });
    }

    const article = await Article.findOneAndUpdate(
      { _id: req.params.id, categorySlug: "photography" },
      { $inc: { views: 1 } },
      { new: true }
    );

    if (!article) {
      return res
        .status(404)
        .json({ success: false, message: "Photo not found" });
    }

    res.json({ success: true, data: { views: article.views } });
  })
);

// DELETE: Photo by ID
app.delete(
  "/api/photography/:id",
  asyncHandler(async (req, res) => {
    if (!validId(req.params.id)) {
      return res.status(400).json({ success: false, message: "Invalid ID" });
    }

    const article = await Article.findOne({
      _id: req.params.id,
      categorySlug: "photography",
    });

    if (!article) {
      return res
        .status(404)
        .json({ success: false, message: "Photo not found" });
    }

    // Delete from Cloudinary
    if (article.img.publicId) {
      try {
        await cloudinary.uploader.destroy(article.img.publicId);
      } catch (err) {
        console.error("Cloudinary delete error:", err);
      }
    }

    // Delete associated comments
    await Promise.all([
      Comment.deleteMany({ articleId: article._id }),
      Article.deleteOne({ _id: article._id }),
    ]);

    res.json({ success: true, message: "Photo deleted successfully" });
  })
);

// ────────────────────── ARTICLE ROUTES ──────────────────────

// Create Article by category slug
app.post(
  "/articles/:categorySlug",
  upload,
  asyncHandler(async (req, res) => {
    const category = await Category.findOne({ slug: req.params.categorySlug });
    if (!category)
      return res
        .status(404)
        .json({ success: false, message: "Category not found" });

    const { error, value } = Joi.object({
      title: Joi.string().min(5).required(),
      description: Joi.string().min(20).required(),
    }).validate(req.body);
    if (error)
      return res
        .status(400)
        .json({ success: false, message: error.details[0].message });
    if (!req.file)
      return res
        .status(400)
        .json({ success: false, message: "Image required" });

    const { secure_url, public_id } = await uploadImg(req.file.buffer);
    const article = await Article.create({
      ...value,
      img: { url: secure_url, publicId: public_id },
      category: category._id,
      categorySlug: category.slug,
    });

    res.status(201).json({ success: true, data: article });
  })
);

// Get Single Article by ID and Category Slug
app.get(
  "/api/article-:categorySlug/:id",
  asyncHandler(async (req, res) => {
    const { id, categorySlug } = req.params;
    if (!validId(id))
      return res.status(400).json({ success: false, message: "Invalid ID" });

    const article = await Article.findOne({
      _id: id,
      categorySlug,
    }).populate("category", "name slug");

    if (!article)
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });

    const commentCount = await Comment.countDocuments({ articleId: id });

    res.json({
      success: true,
      data: {
        ...article.toObject(),
        _id: article._id.toString(),
        timeAgo: timeAgo(article.createdAt),
        comments: commentCount,
      },
    });
  })
);

// Get Articles by Category Slug
app.get(
  "/api/article-:categorySlug",
  asyncHandler(async (req, res) => {
    const { categorySlug } = req.params;
    const page = parseInt(req.query.page || "1");
    const limit = parseInt(req.query.limit || "10");

    const articles = await Article.find({ categorySlug })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const total = await Article.countDocuments({ categorySlug });

    const articleIds = articles.map((a) => a._id);
    const commentCounts = await Comment.aggregate([
      { $match: { articleId: { $in: articleIds } } },
      { $group: { _id: "$articleId", count: { $sum: 1 } } },
    ]);

    const commentMap = Object.fromEntries(
      commentCounts.map((c) => [c._id.toString(), c.count])
    );

    res.json({
      success: true,
      data: articles.map((a) => ({
        ...a,
        _id: a._id.toString(),
        timeAgo: timeAgo(a.createdAt),
        comments: commentMap[a._id.toString()] || 0,
      })),
      pagination: { page, total, pages: Math.ceil(total / limit) },
    });
  })
);

// Increment View Count
app.post(
  "/api/article-:categorySlug/:id/view",
  asyncHandler(async (req, res) => {
    const { id, categorySlug } = req.params;

    if (!validId(id))
      return res.status(400).json({ success: false, message: "Invalid ID" });

    const article = await Article.findOneAndUpdate(
      { _id: id, categorySlug },
      { $inc: { views: 1 } },
      { new: true }
    );

    if (!article)
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });

    res.json({ success: true, data: { views: article.views } });
  })
);

// Get Comments
app.get(
  "/api/article-:categorySlug/:id/comments",
  asyncHandler(async (req, res) => {
    const { id, categorySlug } = req.params;

    if (!validId(id))
      return res.status(400).json({ success: false, message: "Invalid ID" });

    const article = await Article.findOne({ _id: id, categorySlug });
    if (!article)
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });

    const comments = await Comment.find({ articleId: id })
      .sort({ createdAt: -1 })
      .lean();

    res.json({ success: true, data: comments });
  })
);

// Add Comment
app.post(
  "/api/article-:categorySlug/:id/comments",
  asyncHandler(async (req, res) => {
    const { id, categorySlug } = req.params;

    if (!validId(id))
      return res.status(400).json({ success: false, message: "Invalid ID" });

    const article = await Article.findOne({ _id: id, categorySlug });
    if (!article)
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });

    const { error, value } = Joi.object({
      text: Joi.string().min(1).max(1000).required().trim(),
      author: Joi.string().max(50).default("Anonymous"),
    }).validate(req.body);

    if (error)
      return res
        .status(400)
        .json({ success: false, message: error.details[0].message });

    const userHash = getUserHash(req);
    const comment = await Comment.create({
      articleId: id,
      text: value.text,
      author: value.author || "Anonymous",
      userHash,
    });

    res.status(201).json({ success: true, data: comment });
  })
);

// Share
app.post(
  "/api/article-:categorySlug/:id/share",
  asyncHandler(async (req, res) => {
    const { id, categorySlug } = req.params;

    if (!validId(id))
      return res.status(400).json({ success: false, message: "Invalid ID" });

    const article = await Article.findOne({ _id: id, categorySlug });
    if (!article)
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });

    res.json({ success: true, message: "Shared successfully" });
  })
);

// ────────────────────── HEALTH & ERROR ──────────────────────
app.get("/", (_, res) =>
  res.json({
    name: "Masud ibn Belat API",
    status: "running",
    time: new Date().toLocaleString("en-US", { timeZone: "Asia/Dhaka" }),
  })
);

app.get("/health", (_, res) =>
  res.json({
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    uptime: process.uptime(),
  })
);

app.use((_, res) =>
  res.status(404).json({ success: false, message: "Route not found" })
);

app.use((err, _, res, __) => {
  console.error("Error:", err.message);
  res
    .status(err.status || 500)
    .json({ success: false, message: err.message || "Server Error" });
});

// ────────────────────── START SERVER ──────────────────────
const PORT = process.env.PORT || 5000;

// Only start server if not in serverless environment
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, async () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(
      `BD Time: ${new Date().toLocaleString("en-US", {
        timeZone: "Asia/Dhaka",
      })}`
    );
    await connectDB();
  });
}

export default app;
