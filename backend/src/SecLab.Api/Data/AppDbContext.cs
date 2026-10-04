using Microsoft.EntityFrameworkCore;
using SecLab.Api.Models;

namespace SecLab.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Friendship> Friendships => Set<Friendship>();
    public DbSet<Blog> Blogs => Set<Blog>();
    public DbSet<BlogLike> BlogLikes => Set<BlogLike>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Friendship>().HasKey(f => new { f.UserId, f.FriendId });
        b.Entity<BlogLike>().HasKey(l => new { l.UserId, l.BlogId });
    }
}
