using SecLab.Api.Models;

namespace SecLab.Api.Data;

public static class Seed
{
    // All seeded users share the password "password123" (plaintext, on purpose).
    public static void Run(AppDbContext db)
    {
        db.Database.EnsureCreated();
        if (db.Users.Any()) return;

        var names = new[] { ("alice", "Alice Andersen", "Admin"), ("bob", "Bob Berg", "User"),
            ("carol", "Carol Christensen", "User"), ("dave", "Dave Dahl", "User"), ("eve", "Eve Eriksen", "User") };
        var users = names.Select((n, i) => new User
        {
            Username = n.Item1, Password = "password123", DisplayName = n.Item2, Role = n.Item3,
            Email = $"{n.Item1}@example.com", Phone = $"+47 900 00 00{i}", Address = $"Storgata {i + 1}, Oslo",
            AvatarUrl = $"https://i.pravatar.cc/150?u={n.Item1}", Bio = $"Hi, I'm {n.Item2}."
        }).ToList();
        db.Users.AddRange(users);
        db.SaveChanges();

        // alice-bob, alice-carol, bob-dave, carol-eve (stored in both directions)
        foreach (var (a, b) in new[] { (0, 1), (0, 2), (1, 3), (2, 4) })
        {
            db.Friendships.Add(new Friendship { UserId = users[a].Id, FriendId = users[b].Id });
            db.Friendships.Add(new Friendship { UserId = users[b].Id, FriendId = users[a].Id });
        }

        var topics = new[] { "Getting started with .NET", "Why I love React", "Weekend hiking trip", "Coffee brewing 101",
            "Notes on SQL indexes", "My reading list", "Home lab setup", "Cycling to work" };
        var rnd = new Random(42);
        for (var i = 0; i < 20; i++)
            db.Blogs.Add(new Blog
            {
                AuthorId = users[i % users.Count].Id, Title = topics[i % topics.Length] + $" #{i + 1}",
                Body = $"<p>This is blog post {i + 1}. Lorem ipsum dolor sit amet.</p>",
                CreatedAt = DateTime.UtcNow.AddHours(-i * 5)
            });
        db.SaveChanges();

        var blogIds = db.Blogs.Select(b => b.Id).ToList();
        foreach (var u in users)
            foreach (var bid in blogIds.OrderBy(_ => rnd.Next()).Take(4))
                db.BlogLikes.Add(new BlogLike { UserId = u.Id, BlogId = bid });
        db.SaveChanges();
    }
}
