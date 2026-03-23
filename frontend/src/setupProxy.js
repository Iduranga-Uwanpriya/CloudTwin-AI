const { createProxyMiddleware } = require("http-proxy-middleware");

module.exports = function (app) {
  // In Docker: backend is at http://cloudtwin-backend:8000
  // Locally: backend is at http://localhost:8000
  const target = process.env.REACT_APP_API_URL || "http://localhost:8000";

  app.use(
    "/api",
    createProxyMiddleware({
      target,
      changeOrigin: true,
    })
  );
};
