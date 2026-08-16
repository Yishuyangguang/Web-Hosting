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

    // 2. 动态读取环境变量验证管理员权限（零硬编码）
    const ADMIN_PWD = env.SECRET_PWD || env.SECRET_TOKEN || env.ADMIN_PWD;

    function checkAdminAuth() {
      if (!ADMIN_PWD) return false;
      const token = request.headers.get("x-admin-auth") || url.searchParams.get("adminAuth");
      return Boolean(token && token === ADMIN_PWD);
    }

    /* ==========================================================
       🌐 核心路由 1：公开短链页面分发 (/p/:slug)
    ========================================================== */
    if (url.pathname.startsWith("/p/")) {
      const slug = url.pathname.slice(3).replace(/\/+$/, "").trim().toLowerCase();
      if (!slug || !bucket) {
        return new Response("Page Not Found", { status: 404 });
      }

      const r2Key = `_pages/${slug}.html`;
      const object = await bucket.get(r2Key);

      if (!object) {
        return new Response(`
          <!DOCTYPE html>
          <html lang="zh-CN">
          <head>
            <meta charset="UTF-8"><title>404 - 页面未找到</title>
            <style>
              body { font-family: -apple-system, sans-serif; background: #fffbeb; color: #1f2937; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
              .box { text-align: center; background: rgba(255,255,255,0.85); padding: 40px 48px; border-radius: 20px; border: 1px solid #fde68a; box-shadow: 0 10px 25px rgba(245,158,11,0.1); }
              h1 { font-size: 48px; color: #f59e0b; margin: 0 0 12px; }
              p { font-size: 16px; color: #6b7280; margin-bottom: 24px; }
              a { display: inline-block; padding: 10px 20px; background: #f59e0b; color: #fff; text-decoration: none; border-radius: 20px; font-weight: 600; }
            </style>
          </head>
          <body>
            <div class="box">
              <h1>404</h1>
              <p>抱歉，您访问的单页不存在或已被下线。</p>
              <a href="/">返回一束阳光</a>
            </div>
          </body>
          </html>
        `, {
          status: 404,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }

      // 检查页面独立访问密码
      const pageMeta = object.customMetadata || {};
      const requiredPassword = pageMeta.password;
      const clientPass = url.searchParams.get("pwd") || request.headers.get("x-page-password");

      if (requiredPassword && clientPass !== requiredPassword) {
        return new Response(`
          <!DOCTYPE html>
          <html lang="zh-CN">
          <head>
            <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>私密单页访问验证 - 一束阳光</title>
            <style>
              body { font-family: -apple-system, sans-serif; background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%); color: #1f2937; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 16px; }
              .card { background: rgba(255,255,255,0.92); backdrop-filter: blur(12px); border: 1px solid #fde68a; border-radius: 20px; padding: 32px 28px; width: 100%; max-width: 360px; box-shadow: 0 12px 32px rgba(245,158,11,0.12); text-align: center; }
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
              <p>该单页已被作者设置密码保护，请输入密码继续：</p>
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

      // 正常分发 HTML
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
       🛠️ API 管理路由 (/api/page/*)
    ========================================================== */
    if (url.pathname.startsWith("/api/page/")) {
      if (!bucket) {
        return new Response(JSON.stringify({ error: "未检测到 R2 存储桶" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
        });
      }

      // 1. 获取所有已托管单页列表
      if (url.pathname === "/api/page/list" && request.method === "GET") {
        if (!checkAdminAuth()) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });

        const listed = await bucket.list({ prefix: "_pages/" });
        const pages = [];

        for (const obj of (listed.objects || [])) {
          if (!obj.key.endsWith(".html")) continue;
          const slug = obj.key.slice("_pages/".length, -5);
          const meta = obj.customMetadata || {};
          pages.push({
            slug,
            title: meta.title ? decodeURIComponent(meta.title) : slug,
            size: obj.size,
            date: obj.uploaded ? obj.uploaded.toISOString().split("T")[0] : "-",
            hasPassword: Boolean(meta.password)
          });
        }

        pages.sort((a, b) => b.slug.localeCompare(a.slug));
        return new Response(JSON.stringify({ pages }), {
          headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
        });
      }

      // 2. 读取单页原始 HTML 源码（供回填编辑）
      if (url.pathname === "/api/page/get" && request.method === "GET") {
        if (!checkAdminAuth()) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
        const slug = url.searchParams.get("slug");
        if (!slug) return new Response("Missing slug", { status: 400, headers: corsHeaders });

        const object = await bucket.get(`_pages/${slug}.html`);
        if (!object) return new Response("Not Found", { status: 404, headers: corsHeaders });

        const html = await object.text();
        const meta = object.customMetadata || {};
        return new Response(JSON.stringify({
          slug,
          title: meta.title ? decodeURIComponent(meta.title) : slug,
          password: meta.password || "",
          html
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
        });
      }

      // 3. 发布 / 更新单页
      if (url.pathname === "/api/page/publish" && request.method === "POST") {
        if (!checkAdminAuth()) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });

        const { title, slug, html, password } = await request.json();
        const cleanSlug = (slug || Math.random().toString(36).substring(2, 8)).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");

        if (!cleanSlug || !html) {
          return new Response(JSON.stringify({ error: "Slug 或 HTML 内容不能为空" }), { status: 400, headers: corsHeaders });
        }

        const customMetadata = {
          title: encodeURIComponent(title || cleanSlug),
          updatedAt: new Date().toISOString()
        };
        if (password && password.trim()) {
          customMetadata.password = password.trim();
        }

        await bucket.put(`_pages/${cleanSlug}.html`, html, {
          httpMetadata: { contentType: "text/html; charset=utf-8" },
          customMetadata
        });

        return new Response(JSON.stringify({ success: true, slug: cleanSlug, url: `/p/${cleanSlug}` }), {
          headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
        });
      }

      // 4. 下线删除单页
      if (url.pathname === "/api/page/delete" && request.method === "POST") {
        if (!checkAdminAuth()) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
        const { slug } = await request.json();
        if (!slug) return new Response("Missing slug", { status: 400, headers: corsHeaders });

        await bucket.delete(`_pages/${slug}.html`);
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
