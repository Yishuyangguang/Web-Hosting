export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. 自动绑定 R2 存储桶
    let bucket = env.BUCKET || env.MY_BUCKET || env.R2 || env.R2_BUCKET || env.PAN || env.FILES || env.FILE_BUCKET;
    if (!bucket) {
      bucket = Object.values(env).find(v => v && typeof v.list === 'function' && typeof v.get === 'function');
    }

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-admin-auth, Range",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    function jsonResponse(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
      });
    }

    // 从 HTML 代码中智能提取 <title>
    function extractTitleFromHtml(html) {
      if (!html) return "";
      const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      return match ? match[1].trim() : "";
    }

    const ADMIN_PWD = env.SECRET_PWD || env.SECRET_TOKEN || env.ADMIN_PWD;

    function checkAdminAuth() {
      if (!ADMIN_PWD) return false;
      const token = request.headers.get("x-admin-auth") || url.searchParams.get("adminAuth");
      return Boolean(token && token === ADMIN_PWD);
    }

    /* ==========================================================
       🌐 1. 公开短链单页访问 (/p/:slug)
    ========================================================== */
    if (url.pathname.startsWith("/p/")) {
      const rawSlug = url.pathname.slice(3).replace(/\/+$/, "").trim();
      if (!rawSlug || !bucket) {
        return new Response("Page Not Found", { status: 404 });
      }

      const slug = rawSlug.toLowerCase();
      const r2Key = `_pages/${slug}.html`;
      const object = await bucket.get(r2Key);

      if (!object) {
        return new Response(`
          <!DOCTYPE html>
          <html lang="zh-CN">
          <head>
            <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>404 - 页面未找到</title>
            <style>
              body { font-family: -apple-system, sans-serif; background: #fffbeb; color: #1f2937; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
              .box { text-align: center; background: rgba(255,255,255,0.9); padding: 40px 48px; border-radius: 20px; border: 1px solid #fde68a; box-shadow: 0 10px 25px rgba(245,158,11,0.1); }
              h1 { font-size: 48px; color: #f59e0b; margin: 0 0 12px; }
              p { font-size: 16px; color: #6b7280; margin-bottom: 24px; }
              a { display: inline-block; padding: 10px 20px; background: #f59e0b; color: #fff; text-decoration: none; border-radius: 20px; font-weight: 600; }
            </style>
          </head>
          <body>
            <div class="box">
              <h1>404</h1>
              <p>抱歉，您访问的单页不存在或已被作者下线。</p>
              <a href="/">返回一束阳光</a>
            </div>
          </body>
          </html>
        `, {
          status: 404,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }

      const pageMeta = object.customMetadata || {};
      const requiredPassword = pageMeta.password;
      const clientPass = url.searchParams.get("pwd") || request.headers.get("x-page-password");

      if (requiredPassword && clientPass !== requiredPassword) {
        return new Response(`
          <!DOCTYPE html>
          <html lang="zh-CN">
          <head>
            <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>私密单页验证 - 一束阳光</title>
            <style>
              body { font-family: -apple-system, sans-serif; background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%); color: #1f2937; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 16px; }
              .card { background: rgba(255,255,255,0.94); backdrop-filter: blur(12px); border: 1px solid #fde68a; border-radius: 20px; padding: 32px 28px; width: 100%; max-width: 360px; box-shadow: 0 12px 32px rgba(245,158,11,0.12); text-align: center; }
              .icon { font-size: 40px; margin-bottom: 12px; }
              h2 { margin: 0 0 8px; font-size: 19px; }
              p { color: #6b7280; font-size: 13px; margin: 0 0 20px; }
              input { width: 100%; box-sizing: border-box; padding: 12px 14px; border: 1px solid #e5e7eb; border-radius: 12px; font-size: 15px; outline: none; margin-bottom: 14px; text-align: center; }
              input:focus { border-color: #f59e0b; box-shadow: 0 0 0 3px rgba(245,158,11,0.15); }
              button { width: 100%; padding: 12px; background: #f59e0b; color: #fff; border: none; border-radius: 12px; font-size: 15px; font-weight: 600; cursor: pointer; transition: 0.2s; }
              button:hover { background: #d97706; }
            </style>
          </head>
          <body>
            <div class="card">
              <div class="icon">🔒</div>
              <h2>访问受限页面</h2>
              <p>该单页已被设置密码保护，请输入密码继续：</p>
              <form onsubmit="event.preventDefault(); location.href = location.pathname + '?pwd=' + encodeURIComponent(document.getElementById('pwdInput').value);">
                <input type="password" id="pwdInput" placeholder="输入访问密码..." required autofocus />
                <button type="submit">解锁并浏览</button>
              </form>
            </div>
          </body>
          </html>
        `, {
          status: 401,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }

      const htmlBody = await object.text();
      return new Response(htmlBody, {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400"
        }
      });
    }

    /* ==========================================================
       🛠️ 2. API 管理接口
    ========================================================== */
    try {
      if (url.pathname === "/api/auth/verify" && request.method === "POST") {
        return jsonResponse({ valid: checkAdminAuth() });
      }

      if (url.pathname.startsWith("/api/page/")) {
        if (!bucket) {
          return jsonResponse({ error: "未检测到绑定的 R2 存储桶" }, 500);
        }

        // 获取列表（显式 include customMetadata）
        if (url.pathname === "/api/page/list" && request.method === "GET") {
          if (!checkAdminAuth()) return jsonResponse({ error: "Unauthorized" }, 401);

          const listed = await bucket.list({
            prefix: "_pages/",
            include: ["customMetadata", "httpMetadata"]
          });

          const pages = [];
          for (const obj of (listed.objects || [])) {
            if (!obj.key.endsWith(".html")) continue;
            const slug = obj.key.slice("_pages/".length, -5);
            const meta = obj.customMetadata || {};
            
            let displayTitle = slug;
            if (meta.title) {
              try { displayTitle = decodeURIComponent(meta.title); } catch (_) { displayTitle = meta.title; }
            }

            pages.push({
              slug,
              title: displayTitle,
              size: obj.size,
              date: obj.uploaded ? obj.uploaded.toISOString().split("T")[0] : "-",
              hasPassword: Boolean(meta.password)
            });
          }

          pages.sort((a, b) => b.slug.localeCompare(a.slug));
          return jsonResponse({ success: true, pages });
        }

        // 获取源码
        if (url.pathname === "/api/page/get" && request.method === "GET") {
          if (!checkAdminAuth()) return jsonResponse({ error: "Unauthorized" }, 401);
          const slug = (url.searchParams.get("slug") || "").trim().toLowerCase();
          if (!slug) return jsonResponse({ error: "缺少 slug 参数" }, 400);

          const object = await bucket.get(`_pages/${slug}.html`);
          if (!object) return jsonResponse({ error: "页面不存在" }, 404);

          const html = await object.text();
          const meta = object.customMetadata || {};
          let title = slug;
          if (meta.title) {
            try { title = decodeURIComponent(meta.title); } catch (_) { title = meta.title; }
          } else {
            title = extractTitleFromHtml(html) || slug;
          }

          return jsonResponse({
            success: true,
            slug,
            title,
            password: meta.password || "",
            html
          });
        }

        // 发布 / 覆盖单页
        if (url.pathname === "/api/page/publish" && request.method === "POST") {
          if (!checkAdminAuth()) return jsonResponse({ error: "Unauthorized" }, 401);

          let reqData;
          try {
            reqData = await request.json();
          } catch (_) {
            return jsonResponse({ error: "请求格式不合规" }, 400);
          }

          const { slug, html, password } = reqData;
          let { title } = reqData;

          if (!html || !html.trim()) {
            return jsonResponse({ error: "HTML 源码不能为空" }, 400);
          }

          // 自动抓取标题
          if (!title || !title.trim()) {
            title = extractTitleFromHtml(html);
          }

          let cleanSlug = (slug || "").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
          if (!cleanSlug) {
            cleanSlug = "p" + Math.random().toString(36).substring(2, 7);
          }

          const finalTitle = (title && title.trim()) ? title.trim() : cleanSlug;

          const customMetadata = {
            title: encodeURIComponent(finalTitle.slice(0, 100)),
            updatedAt: new Date().toISOString()
          };

          if (password && password.trim()) {
            customMetadata.password = password.trim();
          }

          await bucket.put(`_pages/${cleanSlug}.html`, html, {
            httpMetadata: { contentType: "text/html; charset=utf-8" },
            customMetadata
          });

          return jsonResponse({ success: true, slug: cleanSlug, title: finalTitle, url: `/p/${cleanSlug}` });
        }

        // 删除单页
        if (url.pathname === "/api/page/delete" && request.method === "POST") {
          if (!checkAdminAuth()) return jsonResponse({ error: "Unauthorized" }, 401);
          const { slug } = await request.json();
          if (!slug) return jsonResponse({ error: "缺少 slug 参数" }, 400);

          await bucket.delete(`_pages/${slug.toLowerCase()}.html`);
          return jsonResponse({ success: true });
        }
      }

      if (url.pathname.startsWith("/api/")) {
        return jsonResponse({ error: "API Route Not Found" }, 404);
      }

    } catch (err) {
      return jsonResponse({ error: err.message || "服务器处理异常" }, 500);
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
