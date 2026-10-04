namespace SecLab.Api.Models;

// INTENTIONALLY INSECURE: entities double as API contracts, Password is a plaintext column.
public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Email { get; set; } = "";
    public string Phone { get; set; } = "";
    public string Address { get; set; } = "";
    public string AvatarUrl { get; set; } = "";
    public string Bio { get; set; } = "";
    public string Role { get; set; } = "User";
}

public class Friendship
{
    public int UserId { get; set; }
    public int FriendId { get; set; }
}

public class Blog
{
    public int Id { get; set; }
    public int AuthorId { get; set; }
    public string Title { get; set; } = "";
    public string Body { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class BlogLike
{
    public int UserId { get; set; }
    public int BlogId { get; set; }
}
