import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import Joi from "joi";
import crypto from "crypto";
import compression from "compression";
import helmet from "helmet";

dotenv.config();

// ═══════════════════════════════════════════════════════════════
// 🔥 DATABASE MANAGER
// ═══════════════════════════════════════════════════════════════
class DatabaseManager {
  constructor() {
    this.isConnected = false;
    this.connectionPromise = null;
    this.reconnectAttempts = 0;
    this.MAX_RECONNECT_ATTEMPTS = 5;
    this.setupMongoose();
  }

  setupMongoose() {
    mongoose.set("strictQuery", false);
    mongoose.set("bufferCommands", false);

    mongoose.connection.on("connected", () => {
      this.isConnected = true;
      this.reconnectAttempts = 0;
      console.log("✅ MongoDB Connected");
    });

    mongoose.connection.on("disconnected", () => {
      this.isConnected = false;
      console.log("⚠️ MongoDB Disconnected");
      this.handleReconnect();
    });

    mongoose.connection.on("error", (err) => {
      console.error("❌ MongoDB Error:", err.message);
      this.isConnected = false;
    });
  }

  handleReconnect() {
    if (this.reconnectAttempts >= this.MAX_RECONNECT_ATTEMPTS) {
      console.error("❌ Max reconnection attempts reached");
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

    console.log(
      `🔄 Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`
    );

    setTimeout(() => {
      this.connectionPromise = null;
      this.connect().catch(console.error);
    }, delay);
  }

  async connect() {
    if (this.isConnected && mongoose.connection.readyState === 1) {
      return mongoose.connection;
    }

    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    if (!process.env.MONGODB_URI) {
      throw new Error("MONGODB_URI is not defined in environment variables");
    }

    this.connectionPromise = mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4,
    });

    return this.connectionPromise;
  }

  async healthCheck() {
    try {
      if (!this.isConnected || mongoose.connection.readyState !== 1) {
        return false;
      }
      await mongoose.connection.db.admin().ping();
      return true;
    } catch {
      return false;
    }
  }

  async disconnect() {
    if (this.isConnected) {
      await mongoose.connection.close();
      this.isConnected = false;
    }
  }
}

const db = new DatabaseManager();

// ═══════════════════════════════════════════════════════════════
// 🎨 CLOUDINARY MANAGER
// ═══════════════════════════════════════════════════════════════
class CloudinaryManager {
  constructor() {
    const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET } =
      process.env;

    if (
      !CLOUDINARY_CLOUD_NAME ||
      !CLOUDINARY_API_KEY ||
      !CLOUDINARY_API_SECRET
    ) {
      throw new Error(
        "Missing Cloudinary configuration in environment variables"
      );
    }

    cloudinary.config({
      cloud_name: CLOUDINARY_CLOUD_NAME,
      api_key: CLOUDINARY_API_KEY,
      api_secret: CLOUDINARY_API_SECRET,
    });
  }

  async upload(buffer, folder = "articles") {
    return new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder,
          resource_type: "auto",
          transformation: [{ quality: "auto:good", fetch_format: "auto" }],
        },
        (error, result) => {
          if (error || !result) {
            reject(error || new Error("Upload failed"));
          } else {
            resolve({ url: result.secure_url, publicId: result.public_id });
          }
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
// 🛡️ VALIDATION SCHEMAS
// ═══════════════════════════════════════════════════════════════
const schemas = {
  category: Joi.object({
    name: Joi.string().min(2).max(50).required().trim(),
  }),

  article: Joi.object({
    title: Joi.string().min(5).max(200).required().trim(),
    description: Joi.string().min(20).max(5000).required().trim(),
    categoryId: Joi.string()
      .pattern(/^[0-9a-fA-F]{24}$/)
      .required(),
  }),

  comment: Joi.object({
    text: Joi.string().min(1).max(1000).required().trim(),
    author: Joi.string().max(50).trim().default("Anonymous"),
  }),

  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
    categoryId: Joi.string()
      .pattern(/^[0-9a-fA-F]{24}$/)
      .optional(),
    categorySlug: Joi.string().optional(),
  }),
};

// ═══════════════════════════════════════════════════════════════
// 🗄️ MONGOOSE MODELS
// ═══════════════════════════════════════════════════════════════
const categorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      index: true,
    },
    slug: { type: String, unique: true, trim: true, index: true },
  },
  { timestamps: true, versionKey: false }
);

categorySchema.index({ slug: 1 });

categorySchema.pre("save", function (next) {
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

const Category =
  mongoose.models.Category || mongoose.model("Category", categorySchema);

const articleSchema = new mongoose.Schema(
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
    views: { type: Number, default: 0, min: 0, index: true },
    shares: { type: Number, default: 0, min: 0 },
  },
  { timestamps: true, versionKey: false }
);

articleSchema.index({ category: 1, createdAt: -1 });
articleSchema.index({ views: -1 });

const Article =
  mongoose.models.Article || mongoose.model("Article", articleSchema);

const commentSchema = new mongoose.Schema(
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

commentSchema.index({ articleId: 1, createdAt: -1 });

const Comment =
  mongoose.models.Comment || mongoose.model("Comment", commentSchema);

// ═══════════════════════════════════════════════════════════════
// 🛠️ UTILITIES
// ═══════════════════════════════════════════════════════════════
const Utils = {
  getUserHash(req) {
    const identifier = `${req.ip || req.socket.remoteAddress}|${
      req.headers["user-agent"] || ""
    }`;
    return crypto.createHash("sha256").update(identifier).digest("hex");
  },

  timeAgo(date) {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
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
  },

  validateId(id) {
    return mongoose.Types.ObjectId.isValid(id);
  },

  createSlug(text) {
    return text
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  },
};

// ═══════════════════════════════════════════════════════════════
// 🔄 MIDDLEWARE
// ═══════════════════════════════════════════════════════════════
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const validateBody = (schema) => (req, res, next) => {
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

const validateId =
  (paramName = "id") =>
  (req, res, next) => {
    if (!Utils.validateId(req.params[paramName])) {
      return res.status(400).json({
        success: false,
        message: "Invalid ID format",
      });
    }
    next();
  };

class RateLimiter {
  constructor(windowMs = 60000, maxRequests = 100) {
    this.requests = new Map();
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    setInterval(() => this.requests.clear(), windowMs);
  }

  middleware = (req, res, next) => {
    const key = Utils.getUserHash(req);
    const count = this.requests.get(key) || 0;

    if (count >= this.maxRequests) {
      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later.",
      });
    }

    this.requests.set(key, count + 1);
    next();
  };
}

const commentRateLimiter = new RateLimiter(60000, 10);

// ═══════════════════════════════════════════════════════════════
// 🚀 EXPRESS APP
// ═══════════════════════════════════════════════════════════════
const app = express();

// Security & Performance
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());

// CORS
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",") || true,
    credentials: true,
  })
);

// Body parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.set("trust proxy", 1);

// Database connection middleware
app.use(async (req, res, next) => {
  try {
    await db.connect();
    next();
  } catch (err) {
    console.error("Database connection error:", err);
    res.status(503).json({
      success: false,
      message: "Database unavailable. Please try again later.",
    });
  }
});

// ═══════════════════════════════════════════════════════════════
// 📁 FILE UPLOAD
// ═══════════════════════════════════════════════════════════════
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
    if (!allowedMimes.includes(file.mimetype)) {
      return cb(
        new Error(
          "Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed."
        )
      );
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
          err.code === "LIMIT_FILE_SIZE"
            ? "File too large. Maximum size is 5MB."
            : err.message,
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
  "/api/categories",
  validateBody(schemas.category),
  asyncHandler(async (req, res) => {
    const { name } = req.validatedBody;
    const slug = Utils.createSlug(name);

    const existing = await Category.findOne({
      $or: [{ name: new RegExp(`^${name}$`, "i") }, { slug }],
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Category already exists",
      });
    }

    const category = await Category.create({ name, slug });
    res.status(201).json({ success: true, data: category });
  })
);

app.get(
  "/api/categories",
  asyncHandler(async (req, res) => {
    const categories = await Category.find()
      .select("name slug createdAt")
      .sort({ name: 1 })
      .lean();

    res.json({ success: true, data: categories });
  })
);

app.get(
  "/api/categories/:slug",
  asyncHandler(async (req, res) => {
    const category = await Category.findOne({ slug: req.params.slug })
      .select("name slug _id")
      .lean();

    if (!category) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    res.json({ success: true, data: category });
  })
);

app.delete(
  "/api/categories/:id",
  validateId(),
  asyncHandler(async (req, res) => {
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
        message: `Cannot delete category. ${articleCount} article${
          articleCount > 1 ? "s are" : " is"
        } using this category.`,
      });
    }

    await category.deleteOne();
    res.json({ success: true, message: "Category deleted successfully" });
  })
);

// ═══════════════════════════════════════════════════════════════
// 📝 ARTICLE ROUTES
// ═══════════════════════════════════════════════════════════════
app.post(
  "/api/articles",
  uploadMiddleware,
  validateBody(schemas.article),
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Image is required",
      });
    }

    const { categoryId, title, description } = req.validatedBody;

    const category = await Category.findById(categoryId);
    if (!category) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    const { url, publicId } = await cloudinaryManager.upload(req.file.buffer);

    const article = await Article.create({
      title,
      description,
      img: { url, publicId },
      category: category._id,
    });

    const populatedArticle = await Article.findById(article._id)
      .populate("category", "name slug")
      .lean();

    res.status(201).json({ success: true, data: populatedArticle });
  })
);

app.get(
  "/api/articles",
  asyncHandler(async (req, res) => {
    const { error, value } = schemas.pagination.validate(req.query);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    const { page = 1, limit = 10, categoryId, categorySlug } = value;

    let filter = {};

    // Support both categoryId and categorySlug
    if (categoryId) {
      filter.category = categoryId;
    } else if (categorySlug) {
      const category = await Category.findOne({ slug: categorySlug }).lean();
      if (category) {
        filter.category = category._id;
      }
    }

    const [articles, total] = await Promise.all([
      Article.find(filter)
        .populate("category", "name slug")
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Article.countDocuments(filter),
    ]);

    // Get comment counts
    const articleIds = articles.map((a) => a._id);
    const commentCounts = await Comment.aggregate([
      { $match: { articleId: { $in: articleIds } } },
      { $group: { _id: "$articleId", count: { $sum: 1 } } },
    ]);

    const commentMap = new Map(
      commentCounts.map((c) => [c._id.toString(), c.count])
    );

    res.json({
      success: true,
      data: articles.map((a) => ({
        ...a,
        _id: a._id.toString(),
        timeAgo: Utils.timeAgo(a.createdAt),
        comments: commentMap.get(a._id.toString()) || 0,
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

app.get(
  "/api/articles/:id",
  validateId(),
  asyncHandler(async (req, res) => {
    const [article, commentCount] = await Promise.all([
      Article.findById(req.params.id).populate("category", "name slug").lean(),
      Comment.countDocuments({ articleId: req.params.id }),
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

app.patch(
  "/api/articles/:id",
  validateId(),
  uploadMiddleware,
  asyncHandler(async (req, res) => {
    const article = await Article.findById(req.params.id);
    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    const updates = {};
    if (req.body.title) updates.title = req.body.title.trim();
    if (req.body.description) updates.description = req.body.description.trim();

    if (req.body.categoryId) {
      const category = await Category.findById(req.body.categoryId);
      if (!category) {
        return res.status(404).json({
          success: false,
          message: "Category not found",
        });
      }
      updates.category = category._id;
    }

    if (req.file) {
      // Delete old image
      await cloudinaryManager.delete(article.img.publicId);
      // Upload new image
      const { url, publicId } = await cloudinaryManager.upload(req.file.buffer);
      updates.img = { url, publicId };
    }

    Object.assign(article, updates);
    await article.save();

    const updatedArticle = await Article.findById(article._id)
      .populate("category", "name slug")
      .lean();

    res.json({ success: true, data: updatedArticle });
  })
);

app.post(
  "/api/articles/:id/view",
  validateId(),
  asyncHandler(async (req, res) => {
    const article = await Article.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true, lean: true }
    );

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    res.json({ success: true, data: { views: article.views } });
  })
);

app.post(
  "/api/articles/:id/share",
  validateId(),
  asyncHandler(async (req, res) => {
    const article = await Article.findByIdAndUpdate(
      req.params.id,
      { $inc: { shares: 1 } },
      { new: true, lean: true }
    );

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    res.json({ success: true, data: { shares: article.shares } });
  })
);

app.delete(
  "/api/articles/:id",
  validateId(),
  asyncHandler(async (req, res) => {
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    // Delete everything in parallel
    await Promise.all([
      cloudinaryManager.delete(article.img.publicId),
      Comment.deleteMany({ articleId: article._id }),
      article.deleteOne(),
    ]);

    res.json({ success: true, message: "Article deleted successfully" });
  })
);

// ═══════════════════════════════════════════════════════════════
// 💬 COMMENT ROUTES
// ═══════════════════════════════════════════════════════════════
app.get(
  "/api/articles/:id/comments",
  validateId(),
  asyncHandler(async (req, res) => {
    const article = await Article.findById(req.params.id).lean();
    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    const comments = await Comment.find({ articleId: req.params.id })
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      data: comments.map((c) => ({
        ...c,
        timeAgo: Utils.timeAgo(c.createdAt),
      })),
    });
  })
);

app.post(
  "/api/articles/:id/comments",
  validateId(),
  validateBody(schemas.comment),
  commentRateLimiter.middleware,
  asyncHandler(async (req, res) => {
    const article = await Article.findById(req.params.id).lean();
    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    const { text, author } = req.validatedBody;

    const comment = await Comment.create({
      articleId: req.params.id,
      text,
      author: author || "Anonymous",
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
// 🏥 HEALTH & STATUS
// ═══════════════════════════════════════════════════════════════
app.get("/", (req, res) => {
  res.json({
    name: "Blog API",
    version: "3.0.0",
    status: "operational",
    timestamp: new Date().toISOString(),
  });
});

app.get(
  "/health",
  asyncHandler(async (req, res) => {
    const dbHealthy = await db.healthCheck();

    res.status(dbHealthy ? 200 : 503).json({
      status: dbHealthy ? "healthy" : "degraded",
      database: {
        connected: mongoose.connection.readyState === 1,
        healthy: dbHealthy,
      },
      uptime: process.uptime(),
      memory: process.memoryUsage(),
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
  console.error("Error:", err);

  const statusCode = err.statusCode || err.status || 500;
  const message =
    process.env.NODE_ENV === "production" && statusCode === 500
      ? "Internal server error"
      : err.message || "Something went wrong";

  res.status(statusCode).json({
    success: false,
    message,
  });
});

// ═══════════════════════════════════════════════════════════════
// 🚀 SERVER STARTUP
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 5000;

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, async () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    try {
      await db.connect();
      console.log("📦 Database connected successfully");
    } catch (error) {
      console.error("❌ Database connection failed:", error.message);
    }
  });
}

const shutdown = async (signal) => {
  console.log(`\n${signal} received, shutting down gracefully...`);
  try {
    await db.disconnect();
    console.log("✅ Database disconnected");
    process.exit(0);
  } catch (error) {
    console.error("❌ Error during shutdown:", error);
    process.exit(1);
  }
};

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export default app;
