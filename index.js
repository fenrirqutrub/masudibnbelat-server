import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import Joi from "joi";
import crypto from "crypto";

dotenv.config();

// ═══════════════════════════════════════════════════════════════
// 🔥 ADVANCED MONGODB CONNECTION WITH RETRY & HEALTH CHECKS
// ═══════════════════════════════════════════════════════════════
class DatabaseManager {
  constructor() {
    this.isConnected = false;
    this.connectionPromise = null;
    this.retryAttempts = 0;
    this.maxRetries = 3;
    this.setupMongoose();
  }

  setupMongoose() {
    mongoose.set("strictQuery", false);
    mongoose.set("bufferCommands", false);
    mongoose.set("autoIndex", false);

    mongoose.connection.on("connected", () => {
      this.isConnected = true;
      this.retryAttempts = 0;
      console.log("✅ MongoDB Connected");
    });

    mongoose.connection.on("disconnected", () => {
      this.isConnected = false;
      console.log("⚠️ MongoDB Disconnected");
    });

    mongoose.connection.on("error", (err) => {
      console.error("❌ MongoDB Error:", err.message);
      this.isConnected = false;
    });
  }

  async connect() {
    if (this.isConnected && mongoose.connection.readyState === 1) {
      return mongoose.connection;
    }

    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = this._attemptConnection();
    return this.connectionPromise;
  }

  async _attemptConnection() {
    while (this.retryAttempts < this.maxRetries) {
      try {
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
          maxPoolSize: 5,
          minPoolSize: 1,
          serverSelectionTimeoutMS: 5000,
          socketTimeoutMS: 45000,
          family: 4,
        });

        this.isConnected = true;
        this.connectionPromise = null;
        return conn;
      } catch (err) {
        this.retryAttempts++;
        console.error(
          `❌ Connection attempt ${this.retryAttempts}/${this.maxRetries} failed:`,
          err.message
        );

        if (this.retryAttempts >= this.maxRetries) {
          this.connectionPromise = null;
          throw new Error("Database connection failed after retries");
        }

        await new Promise((resolve) =>
          setTimeout(resolve, 1000 * this.retryAttempts)
        );
      }
    }
  }

  async healthCheck() {
    try {
      if (!this.isConnected) return false;
      await mongoose.connection.db.admin().ping();
      return true;
    } catch {
      return false;
    }
  }
}

const db = new DatabaseManager();

// ═══════════════════════════════════════════════════════════════
// 🎨 CLOUDINARY MANAGER WITH ADVANCED ERROR HANDLING
// ═══════════════════════════════════════════════════════════════
class CloudinaryManager {
  constructor() {
    cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
    });
  }

  async upload(buffer, options = {}) {
    return new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: "articles",
          resource_type: "auto",
          transformation: [{ quality: "auto", fetch_format: "auto" }],
          ...options,
        },
        (error, result) => {
          if (error) reject(error);
          else resolve({ url: result.secure_url, publicId: result.public_id });
        }
      );
      uploadStream.end(buffer);
    });
  }

  async delete(publicId) {
    try {
      await cloudinary.uploader.destroy(publicId);
      return true;
    } catch (error) {
      console.error("Cloudinary delete error:", error);
      return false;
    }
  }
}

const cloudinaryManager = new CloudinaryManager();

// ═══════════════════════════════════════════════════════════════
// 🛡️ ADVANCED VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════
const schemas = {
  category: Joi.object({
    categoryName: Joi.string()
      .min(2)
      .max(50)
      .required()
      .trim()
      .pattern(/^[\p{L}\p{N}\s-]+$/u)
      .messages({
        "string.pattern.base":
          "Only letters, numbers, spaces, and hyphens allowed",
      }),
  }),

  article: Joi.object({
    title: Joi.string().min(5).max(200).required().trim(),
    description: Joi.string().min(20).max(5000).required().trim(),
  }),

  comment: Joi.object({
    text: Joi.string().min(1).max(1000).required().trim(),
    author: Joi.string().max(50).trim().default("Anonymous"),
  }),

  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
  }),
};

// ═══════════════════════════════════════════════════════════════
// 🗄️ ADVANCED MODEL FACTORY WITH CACHING
// ═══════════════════════════════════════════════════════════════
class ModelFactory {
  static getCategory() {
    if (mongoose.models.Category) return mongoose.models.Category;

    const schema = new mongoose.Schema(
      {
        name: {
          type: String,
          required: true,
          unique: true,
          trim: true,
          index: true,
        },
        slug: {
          type: String,
          unique: true,
          trim: true,
          index: true,
        },
      },
      { timestamps: true, versionKey: false }
    );

    schema.pre("save", function (next) {
      if (this.isModified("name")) {
        this.slug = this.name
          .toLowerCase()
          .normalize("NFD")
          .replace(/[\u0300-\u036f]/g, "")
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-+|-+$/g, "");
      }
      next();
    });

    schema.statics.findBySlug = function (slug) {
      return this.findOne({ slug }).lean();
    };

    return mongoose.model("Category", schema);
  }

  static getArticle() {
    if (mongoose.models.Article) return mongoose.models.Article;

    const schema = new mongoose.Schema(
      {
        title: { type: String, required: true, trim: true, index: "text" },
        description: { type: String, required: true, trim: true },
        img: {
          url: { type: String, required: true },
          publicId: { type: String, required: true },
        },
        category: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Category",
          required: true,
          index: true,
        },
        categorySlug: {
          type: String,
          required: true,
          index: true,
        },
        views: { type: Number, default: 0, min: 0 },
      },
      { timestamps: true, versionKey: false }
    );

    schema.index({ categorySlug: 1, createdAt: -1 });

    schema.statics.incrementViews = async function (id, categorySlug) {
      return this.findOneAndUpdate(
        { _id: id, categorySlug },
        { $inc: { views: 1 } },
        { new: true, lean: true }
      );
    };

    schema.statics.findByCategorySlug = function (categorySlug, options = {}) {
      const { page = 1, limit = 10 } = options;
      return this.find({ categorySlug })
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean();
    };

    return mongoose.model("Article", schema);
  }

  static getComment() {
    if (mongoose.models.Comment) return mongoose.models.Comment;

    const schema = new mongoose.Schema(
      {
        articleId: {
          type: mongoose.Schema.Types.ObjectId,
          required: true,
          ref: "Article",
          index: true,
        },
        text: { type: String, required: true, trim: true, maxlength: 1000 },
        author: { type: String, default: "Anonymous", trim: true },
        userHash: { type: String, required: true, index: true },
      },
      { timestamps: true, versionKey: false }
    );

    schema.index({ articleId: 1, createdAt: -1 });

    schema.statics.getCommentCounts = async function (articleIds) {
      const counts = await this.aggregate([
        { $match: { articleId: { $in: articleIds } } },
        { $group: { _id: "$articleId", count: { $sum: 1 } } },
      ]);
      return new Map(counts.map((c) => [c._id.toString(), c.count]));
    };

    return mongoose.model("Comment", schema);
  }
}

// ═══════════════════════════════════════════════════════════════
// 🛠️ UTILITY CLASSES
// ═══════════════════════════════════════════════════════════════
class Utils {
  static getUserHash(req) {
    const identifier = `${req.ip || req.connection.remoteAddress}|${
      req.headers["user-agent"] || ""
    }`;
    return crypto.createHash("sha256").update(identifier).digest("hex");
  }

  static timeAgo(date) {
    const seconds = Math.floor((Date.now() - new Date(date)) / 1000);
    const intervals = [
      { label: "year", seconds: 31536000 },
      { label: "month", seconds: 2592000 },
      { label: "day", seconds: 86400 },
      { label: "hour", seconds: 3600 },
      { label: "minute", seconds: 60 },
    ];

    for (const interval of intervals) {
      const count = Math.floor(seconds / interval.seconds);
      if (count >= 1) {
        return `${count} ${interval.label}${count > 1 ? "s" : ""} ago`;
      }
    }
    return "just now";
  }

  static validateId(id) {
    return mongoose.Types.ObjectId.isValid(id);
  }

  static createSlug(text) {
    return text
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  static validatePagination(query) {
    const { error, value } = schemas.pagination.validate(query, {
      allowUnknown: true,
      stripUnknown: true,
    });
    if (error) throw new Error(error.details[0].message);
    return value;
  }
}

// ═══════════════════════════════════════════════════════════════
// 🔄 MIDDLEWARE FACTORY
// ═══════════════════════════════════════════════════════════════
class Middleware {
  static asyncHandler(fn) {
    return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  }

  static validateBody(schema) {
    return (req, res, next) => {
      const { error, value } = schema.validate(req.body);
      if (error) {
        return res.status(400).json({
          success: false,
          message: error.details[0].message,
        });
      }
      req.validatedBody = value;
      next();
    };
  }

  static validateId(paramName = "id") {
    return (req, res, next) => {
      if (!Utils.validateId(req.params[paramName])) {
        return res.status(400).json({
          success: false,
          message: "Invalid ID format",
        });
      }
      next();
    };
  }

  static async ensureDatabase(req, res, next) {
    try {
      await db.connect();
      next();
    } catch (error) {
      res.status(503).json({
        success: false,
        message: "Database temporarily unavailable",
      });
    }
  }

  static rateLimit(windowMs = 60000, maxRequests = 100) {
    const requests = new Map();
    return (req, res, next) => {
      const key = Utils.getUserHash(req);
      const now = Date.now();
      const userRequests = requests.get(key) || [];

      const recentRequests = userRequests.filter(
        (timestamp) => now - timestamp < windowMs
      );

      if (recentRequests.length >= maxRequests) {
        return res.status(429).json({
          success: false,
          message: "Too many requests",
        });
      }

      recentRequests.push(now);
      requests.set(key, recentRequests);
      next();
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// 🚀 EXPRESS APP SETUP
// ═══════════════════════════════════════════════════════════════
const app = express();

app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",") || true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  })
);

app.use(async (req, res, next) => {
  try {
    await db.connect();
    next();
  } catch (err) {
    return res.status(503).json({
      success: false,
      message: "Database temporarily unavailable",
    });
  }
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.set("trust proxy", 1);

// Request logging
if (process.env.NODE_ENV !== "production") {
  app.use((req, res, next) => {
    const start = Date.now();
    res.on("finish", () => {
      console.log(
        `${req.method} ${req.path} ${res.statusCode} - ${Date.now() - start}ms`
      );
    });
    next();
  });
}

// ═══════════════════════════════════════════════════════════════
// 📁 FILE UPLOAD CONFIGURATION
// ═══════════════════════════════════════════════════════════════
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only images allowed"));
    }
    cb(null, true);
  },
}).single("img");

const uploadMiddleware = (req, res, next) => {
  upload(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({
        success: false,
        message:
          err.code === "LIMIT_FILE_SIZE" ? "File too large" : err.message,
      });
    }
    if (err) {
      return res.status(400).json({ success: false, message: err.message });
    }
    next();
  });
};

// ═══════════════════════════════════════════════════════════════
// 📂 CATEGORY ROUTES
// ═══════════════════════════════════════════════════════════════
app.post(
  "/api/category",
  Middleware.validateBody(schemas.category),
  Middleware.asyncHandler(async (req, res) => {
    const Category = ModelFactory.getCategory();
    const { categoryName } = req.validatedBody;

    const slug = Utils.createSlug(categoryName);
    const existing = await Category.findOne({
      $or: [{ name: new RegExp(`^${categoryName}$`, "i") }, { slug }],
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Category already exists",
      });
    }

    const category = await Category.create({
      name: categoryName.trim(),
      slug,
    });

    res.status(201).json({ success: true, data: category });
  })
);

app.get(
  "/api/category",
  Middleware.asyncHandler(async (req, res) => {
    const Category = ModelFactory.getCategory();
    const categories = await Category.find()
      .select("name slug createdAt")
      .sort({ name: 1 })
      .lean();

    res.json({ success: true, data: categories });
  })
);

app.delete(
  "/api/category/:id",
  Middleware.validateId(),
  Middleware.asyncHandler(async (req, res) => {
    const Category = ModelFactory.getCategory();
    const Article = ModelFactory.getArticle();

    const category = await Category.findById(req.params.id);
    if (!category) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    const articleCount = await Article.countDocuments({
      category: category._id,
    });

    if (articleCount > 0) {
      return res.status(409).json({
        success: false,
        message: `Cannot delete: ${articleCount} article${
          articleCount > 1 ? "s" : ""
        } exist`,
      });
    }

    await category.deleteOne();
    res.json({ success: true, message: "Category deleted" });
  })
);

// ═══════════════════════════════════════════════════════════════
// 📸 PHOTOGRAPHY ROUTES
// ═══════════════════════════════════════════════════════════════
app.post(
  "/api/photography",
  uploadMiddleware,
  Middleware.asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Image required",
      });
    }

    const Category = ModelFactory.getCategory();
    const Article = ModelFactory.getArticle();

    let category = await Category.findBySlug("photography");
    if (!category) {
      category = await Category.create({
        name: "Photography",
        slug: "photography",
      });
    }

    const { url, publicId } = await cloudinaryManager.upload(req.file.buffer);

    const article = await Article.create({
      title: req.body.title || "Photography Image",
      description:
        req.body.description || "A beautiful photography moment captured.",
      img: { url, publicId },
      category: category._id,
      categorySlug: "photography",
    });

    res.status(201).json({ success: true, data: article });
  })
);

app.get(
  "/api/photography",
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const { page, limit } = await Utils.validatePagination(req.query);

    const [photos, total] = await Promise.all([
      Article.findByCategorySlug("photography", { page, limit }),
      Article.countDocuments({ categorySlug: "photography" }),
    ]);

    res.json({
      success: true,
      data: photos.map((photo) => ({
        ...photo,
        _id: photo._id.toString(),
        timeAgo: Utils.timeAgo(photo.createdAt),
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasMore: page * limit < total,
      },
    });
  })
);

app.post(
  "/api/photography/:id/view",
  Middleware.validateId(),
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const article = await Article.incrementViews(req.params.id, "photography");

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Photo not found",
      });
    }

    res.json({ success: true, data: { views: article.views } });
  })
);

app.delete(
  "/api/photography/:id",
  Middleware.validateId(),
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const Comment = ModelFactory.getComment();

    const article = await Article.findOne({
      _id: req.params.id,
      categorySlug: "photography",
    });

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Photo not found",
      });
    }

    await Promise.all([
      cloudinaryManager.delete(article.img.publicId),
      Comment.deleteMany({ articleId: article._id }),
      article.deleteOne(),
    ]);

    res.json({ success: true, message: "Photo deleted successfully" });
  })
);

// ═══════════════════════════════════════════════════════════════
// 📝 ARTICLE ROUTES
// ═══════════════════════════════════════════════════════════════
app.post(
  "/articles/:categorySlug",
  uploadMiddleware,
  Middleware.validateBody(schemas.article),
  Middleware.asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Image required",
      });
    }

    const Category = ModelFactory.getCategory();
    const Article = ModelFactory.getArticle();

    const category = await Category.findBySlug(req.params.categorySlug);
    if (!category) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    const { url, publicId } = await cloudinaryManager.upload(req.file.buffer);

    const article = await Article.create({
      title: req.validatedBody.title,
      description: req.validatedBody.description,
      img: { url, publicId },
      category: category._id,
      categorySlug: category.slug,
    });

    res.status(201).json({ success: true, data: article });
  })
);

app.get(
  "/api/article-:categorySlug",
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const Comment = ModelFactory.getComment();
    let { categorySlug } = req.params;

    if (!categorySlug?.trim()) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid category slug" });
    }
    categorySlug = categorySlug.trim();

    // <-- FIXED: no await, synchronous validation
    let page = 1;
    let limit = 10;
    try {
      const validated = Utils.validatePagination(req.query);
      page = validated.page;
      limit = validated.limit;
    } catch (err) {
      return res.status(400).json({ success: false, message: err.message });
    }

    const [articles, total] = await Promise.all([
      Article.findByCategorySlug(categorySlug, { page, limit }),
      Article.countDocuments({ categorySlug }),
    ]);

    const commentCounts =
      articles.length > 0
        ? await Comment.getCommentCounts(articles.map((a) => a._id))
        : new Map();

    res.json({
      success: true,
      data: articles.map((a) => ({
        ...a,
        _id: a._id.toString(),
        timeAgo: Utils.timeAgo(a.createdAt),
        comments: commentCounts.get(a._id.toString()) || 0,
      })),
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        pages: Math.ceil(total / limit),
        hasMore: page * limit < total,
      },
    });
  })
);

app.get(
  "/api/article-:categorySlug/:id",
  Middleware.validateId(),
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const Comment = ModelFactory.getComment();
    const { id, categorySlug } = req.params;

    const [article, commentCount] = await Promise.all([
      Article.findOne({ _id: id, categorySlug })
        .populate("category", "name slug")
        .lean(),
      Comment.countDocuments({ articleId: id }),
    ]);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    res.json({
      success: true,
      data: {
        ...article,
        _id: article._id.toString(),
        timeAgo: Utils.timeAgo(article.createdAt),
        comments: commentCount,
      },
    });
  })
);

app.post(
  "/api/article-:categorySlug/:id/view",
  Middleware.validateId(),
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const { id, categorySlug } = req.params;

    const article = await Article.incrementViews(id, categorySlug);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    res.json({ success: true, data: { views: article.views } });
  })
);

// ═══════════════════════════════════════════════════════════════
// 💬 COMMENT ROUTES
// ═══════════════════════════════════════════════════════════════
app.get(
  "/api/article-:categorySlug/:id/comments",
  Middleware.validateId(),
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const Comment = ModelFactory.getComment();
    const { id, categorySlug } = req.params;

    const article = await Article.findOne({ _id: id, categorySlug }).lean();
    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    const comments = await Comment.find({ articleId: id })
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      data: comments.map((comment) => ({
        ...comment,
        timeAgo: Utils.timeAgo(comment.createdAt),
      })),
    });
  })
);

app.post(
  "/api/article-:categorySlug/:id/comments",
  Middleware.validateId(),
  Middleware.validateBody(schemas.comment),
  Middleware.rateLimit(60000, 10),
  Middleware.asyncHandler(async (req, res) => {
    const Article = ModelFactory.getArticle();
    const Comment = ModelFactory.getComment();
    const { id, categorySlug } = req.params;

    const article = await Article.findOne({ _id: id, categorySlug }).lean();
    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    const comment = await Comment.create({
      articleId: id,
      text: req.validatedBody.text,
      author: req.validatedBody.author || "Anonymous",
      userHash: Utils.getUserHash(req),
    });

    res.status(201).json({
      success: true,
      data: {
        ...comment.toObject(),
        timeAgo: Utils.timeAgo(comment.createdAt),
      },
    });
  })
);

// ═══════════════════════════════════════════════════════════════
// 🏥 HEALTH & STATUS ROUTES
// ═══════════════════════════════════════════════════════════════
app.get("/", (req, res) => {
  res.json({
    name: "Masud ibn Belat API",
    version: "2.0.0",
    status: "operational",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

app.get(
  "/health",
  Middleware.asyncHandler(async (req, res) => {
    const dbHealthy = await db.healthCheck();
    const status = dbHealthy ? "healthy" : "degraded";

    res.status(dbHealthy ? 200 : 503).json({
      status,
      database: {
        connected: db.isConnected,
        healthy: dbHealthy,
        state: mongoose.connection.readyState,
      },
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString(),
    });
  })
);

// ═══════════════════════════════════════════════════════════════
// ⚠️ ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.path} not found`,
  });
});

app.use((err, req, res, next) => {
  console.error("Error:", {
    message: err.message,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
    path: req.path,
    method: req.method,
  });

  const statusCode = err.statusCode || err.status || 500;
  const message =
    process.env.NODE_ENV === "production" && statusCode === 500
      ? "Internal server error"
      : err.message;

  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
  });
});

// ═══════════════════════════════════════════════════════════════
// 🚀 SERVER STARTUP
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 5000;

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, async () => {
    console.log(`
╔══════════════════════════════════════════╗
║  🚀 Server Running                       ║
║  📍 http://localhost:${PORT}             ║
║  🕐 ${new Date().toLocaleString("en-US", { timeZone: "Asia/Dhaka" })}  ║
╚═══════════════════════════════════════════╝
    `);
    await db.connect();
  });
}

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("SIGTERM received, closing gracefully...");
  await mongoose.connection.close();
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("SIGINT received, closing gracefully...");
  await mongoose.connection.close();
  process.exit(0);
});

export default app;
