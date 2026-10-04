using Microsoft.EntityFrameworkCore;
using SecLab.Api.Data;
using SecLab.Api.Models;

namespace SecLab.Api.Endpoints;

// INTENTIONALLY INSECURE. Every weakness below is documented in docs/00-overview-and-threat-model.md
// and is fixed in a tutorial step. Do not "fix" them outside the tutorial.
public static class Api
{
    // WEAKNESS: the "session" is just a header the client chooses.
    static int? CurrentUserId(HttpContext ctx) =>
        int.TryParse(ctx.Request.Headers["X-User-Id"], out var id) ? id : null;

    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api");

        // ---- Auth ----
        api.MapPost("/auth/login", async (LoginRequest req, AppDbContext db) =>
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username && u.Password == req.Password);
            // WEAKNESS: distinct message per failure (user enumeration), plaintext compare, returns whole entity.
            if (user is null) return Results.Unauthorized();
            return Results.Ok(new { token = user.Id.ToString(), user });
        });

        // ---- Profile ----
        // WEAKNESS: IDOR - any caller can read any user, including the Password column.
        api.MapGet("/users/{id:int}", async (int id, AppDbContext db) =>
            await db.Users.FindAsync(id) is { } u ? Results.Ok(u) : Results.NotFound());

        // WEAKNESS: mass assignment - binds the full entity, so Role/Password/Id can be overwritten; no ownership check.
        api.MapPut("/users/{id:int}", async (int id, User update, AppDbContext db) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user is null) return Results.NotFound();
            update.Id = id;
            db.Entry(user).CurrentValues.SetValues(update);
            await db.SaveChangesAsync();
            return Results.Ok(user);
        });

        api.MapGet("/users/{id:int}/friends", async (int id, AppDbContext db) =>
            await db.Friendships.Where(f => f.UserId == id)
                .Join(db.Users, f => f.FriendId, u => u.Id, (f, u) => u).ToListAsync());

        // WEAKNESS: unrestricted upload - original file name, any type, any size, served from wwwroot.
        api.MapPost("/users/{id:int}/avatar", async (int id, IFormFile file, AppDbContext db, IWebHostEnvironment env) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user is null) return Results.NotFound();
            var dir = Path.Combine(env.WebRootPath, "avatars");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, file.FileName);
            await using (var fs = File.Create(path)) await file.CopyToAsync(fs);
            user.AvatarUrl = $"/avatars/{file.FileName}";
            await db.SaveChangesAsync();
            return Results.Ok(new { user.AvatarUrl });
        }).DisableAntiforgery();

        // ---- Blogs ----
        api.MapGet("/blogs", async (AppDbContext db) => await ToViews(db, db.Blogs.OrderByDescending(b => b.CreatedAt)));

        // WEAKNESS: SQL injection - user input concatenated into raw SQL.
        api.MapGet("/blogs/search", async (string q, AppDbContext db) =>
        {
            var sql = "SELECT * FROM Blogs WHERE Title LIKE '%" + q + "%' OR Body LIKE '%" + q + "%'";
            return await ToViews(db, db.Blogs.FromSqlRaw(sql));
        });

        // WEAKNESS: no validation, AuthorId taken from the client body, Body stored/rendered as raw HTML (stored XSS).
        api.MapPost("/blogs", async (Blog blog, AppDbContext db) =>
        {
            blog.Id = 0; blog.CreatedAt = DateTime.UtcNow;
            db.Blogs.Add(blog);
            await db.SaveChangesAsync();
            return Results.Created($"/api/blogs/{blog.Id}", blog);
        });

        api.MapPost("/blogs/{id:int}/like", async (int id, HttpContext ctx, AppDbContext db) =>
        {
            if (CurrentUserId(ctx) is not { } uid) return Results.Unauthorized();
            if (!await db.BlogLikes.AnyAsync(l => l.UserId == uid && l.BlogId == id))
            {
                db.BlogLikes.Add(new BlogLike { UserId = uid, BlogId = id });
                await db.SaveChangesAsync();
            }
            return Results.NoContent();
        });

        api.MapDelete("/blogs/{id:int}/like", async (int id, HttpContext ctx, AppDbContext db) =>
        {
            if (CurrentUserId(ctx) is not { } uid) return Results.Unauthorized();
            await db.BlogLikes.Where(l => l.UserId == uid && l.BlogId == id).ExecuteDeleteAsync();
            return Results.NoContent();
        });

        // Personal page: blogs the user has liked. WEAKNESS: any user id can be requested.
        api.MapGet("/users/{id:int}/likes", async (int id, AppDbContext db) =>
            await ToViews(db, db.Blogs.Where(b => db.BlogLikes.Any(l => l.UserId == id && l.BlogId == b.Id))
                .OrderByDescending(b => b.CreatedAt)));

        // Timeline: blogs by the current user's friends.
        api.MapGet("/timeline", async (HttpContext ctx, AppDbContext db) =>
        {
            if (CurrentUserId(ctx) is not { } uid) return Results.Unauthorized();
            var friends = db.Friendships.Where(f => f.UserId == uid).Select(f => f.FriendId);
            return Results.Ok(await ToViews(db, db.Blogs.Where(b => friends.Contains(b.AuthorId))
                .OrderByDescending(b => b.CreatedAt)));
        });

        // WEAKNESS: crash endpoint used by the error-handling step; developer exception page leaks details.
        api.MapGet("/debug/crash", () => { throw new InvalidOperationException("Boom: connection string is " + "Server=localhost;User Id=sa;..."); });
    }

    public record BlogView(int Id, int AuthorId, string AuthorName, string AuthorAvatar, string Title, string Body, DateTime CreatedAt, int Likes);

    static async Task<List<BlogView>> ToViews(AppDbContext db, IQueryable<Blog> blogs) =>
        await blogs.Select(b => new BlogView(
            b.Id, b.AuthorId,
            db.Users.Where(u => u.Id == b.AuthorId).Select(u => u.DisplayName).FirstOrDefault() ?? "",
            db.Users.Where(u => u.Id == b.AuthorId).Select(u => u.AvatarUrl).FirstOrDefault() ?? "",
            b.Title, b.Body, b.CreatedAt,
            db.BlogLikes.Count(l => l.BlogId == b.Id))).ToListAsync();

    public record LoginRequest(string Username, string Password);
}
