using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecLab.Api.Data;
using SecLab.Api.Models;
using Xunit;

namespace SecLab.Api.Tests;

// Step 05 – Authorization. Every test creates its own users, so seeded data is never modified.
// Rules are specified in docs/05-authorization.md. Roles come from Users.Role in the database.
[Trait("Step", "05")]
public class Step05AuthorizationTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly TestIdp _idp = new();
    public void Dispose() => _idp.Dispose();

    sealed record Person(int Id, string Username, HttpClient Http);

    Person NewPerson(string role = "User")
    {
        var name = "az" + Guid.NewGuid().ToString("N")[..10];
        int id;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var u = new User
            {
                Username = name, DisplayName = "Name " + name, Email = $"{name}@example.com", Phone = "+47 111 11 111",
                Address = "Secret Street 1", Bio = "bio", Role = role, Password = "x",
            };
            db.Users.Add(u); db.SaveChanges(); id = u.Id;
        }
        var http = _idp.CreateClient(factory);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _idp.Token(name));
        return new Person(id, name, http);
    }

    void Befriend(Person a, Person b)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Friendships.Add(new Friendship { UserId = a.Id, FriendId = b.Id });
        db.Friendships.Add(new Friendship { UserId = b.Id, FriendId = a.Id });
        db.SaveChanges();
    }

    int NewBlog(Person author)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var b = new Blog { AuthorId = author.Id, Title = "t", Body = "<p>b</p>" };
        db.Blogs.Add(b); db.SaveChanges(); return b.Id;
    }

    T InDb<T>(Func<AppDbContext, T> f)
    {
        using var scope = factory.Services.CreateScope();
        return f(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    static async Task<JsonElement> Json(HttpResponseMessage res)
    {
        var text = await res.Content.ReadAsStringAsync();
        return string.IsNullOrWhiteSpace(text) ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    static bool Has(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out _);

    // ---- default deny ----

    [Fact]
    public async Task A_fallback_policy_protects_every_endpoint_that_forgets_to_declare_one()
    {
        var policy = await factory.Services.GetRequiredService<IAuthorizationPolicyProvider>().GetFallbackPolicyAsync();
        Assert.NotNull(policy);
        Assert.Contains(policy!.Requirements, r => r is Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement);
    }

    // ---- reading profiles (object-level + property-level) ----

    [Fact]
    public async Task A_stranger_sees_only_the_public_part_of_a_profile()
    {
        var me = NewPerson(); var stranger = NewPerson();

        var res = await stranger.Http.GetAsync($"/api/users/{me.Id}");

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await Json(res);
        Assert.Equal("Name " + me.Username, body.GetProperty("displayName").GetString());
        foreach (var hidden in new[] { "email", "phone", "address", "password", "role", "failedLoginCount", "lockoutEnd", "passwordIsHashed" })
            Assert.False(Has(body, hidden), $"stranger must not see '{hidden}'");
    }

    [Fact]
    public async Task A_friend_also_sees_email_and_phone_but_not_the_address()
    {
        var me = NewPerson(); var friend = NewPerson(); Befriend(me, friend);

        var body = await Json(await friend.Http.GetAsync($"/api/users/{me.Id}"));

        Assert.True(Has(body, "email")); Assert.True(Has(body, "phone"));
        Assert.False(Has(body, "address")); Assert.False(Has(body, "password"));
    }

    [Fact]
    public async Task Users_see_their_whole_profile_but_never_password_material()
    {
        var me = NewPerson();
        var text = await (await me.Http.GetAsync($"/api/users/{me.Id}")).Content.ReadAsStringAsync();
        var body = JsonDocument.Parse(text).RootElement;

        Assert.True(Has(body, "address")); Assert.True(Has(body, "email"));
        Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("lockout", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Admins_can_read_any_full_profile()
    {
        var admin = NewPerson("Admin"); var someone = NewPerson();
        var body = await Json(await admin.Http.GetAsync($"/api/users/{someone.Id}"));
        Assert.True(Has(body, "address"));
    }

    [Fact]
    public async Task Unknown_users_are_404()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await NewPerson().Http.GetAsync("/api/users/2000000000")).StatusCode);
    }

    // ---- writing profiles ----

    [Fact]
    public async Task Nobody_edits_someone_elses_profile()
    {
        var victim = NewPerson(); var attacker = NewPerson(); var admin = NewPerson("Admin");
        var edit = new { displayName = "pwned", email = "e@x.com", phone = "+47 111 22 333", address = "a", bio = "b" };

        Assert.Equal(HttpStatusCode.Forbidden, (await attacker.Http.PutAsJsonAsync($"/api/users/{victim.Id}", edit)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Http.PutAsJsonAsync($"/api/users/{victim.Id}", edit)).StatusCode);
        Assert.Equal("Name " + victim.Username, InDb(db => db.Users.Single(u => u.Id == victim.Id).DisplayName));
    }

    [Fact]
    public async Task Editing_your_own_profile_cannot_change_role_username_password_or_id()
    {
        var me = NewPerson();
        var passwordBefore = InDb(db => db.Users.Single(x => x.Id == me.Id).Password);

        var res = await me.Http.PutAsJsonAsync($"/api/users/{me.Id}", new
        {
            displayName = "New name", email = "new@example.com", phone = "+47 999 88 777", address = "New street 2", bio = "new bio",
            role = "Admin", username = "hacker", password = "hacked", id = 1,
        });

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var u = InDb(db => db.Users.Single(x => x.Id == me.Id));
        Assert.Equal("New name", u.DisplayName);
        Assert.Equal("new@example.com", u.Email);
        Assert.Equal("User", u.Role);
        Assert.Equal(me.Username, u.Username);
        Assert.Equal(passwordBefore, u.Password);
    }

    [Fact]
    public async Task Only_admins_change_roles_and_only_to_known_roles()
    {
        var admin = NewPerson("Admin"); var target = NewPerson(); var user = NewPerson();

        Assert.Equal(HttpStatusCode.Forbidden, (await user.Http.PutAsJsonAsync($"/api/admin/users/{target.Id}/role", new { role = "Admin" })).StatusCode);
        Assert.Equal("User", InDb(db => db.Users.Single(u => u.Id == target.Id).Role));

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.Http.PutAsJsonAsync($"/api/admin/users/{target.Id}/role", new { role = "Root" })).StatusCode);
        Assert.True((await admin.Http.PutAsJsonAsync($"/api/admin/users/{target.Id}/role", new { role = "Admin" })).IsSuccessStatusCode);
        Assert.Equal("Admin", InDb(db => db.Users.Single(u => u.Id == target.Id).Role));
    }

    [Fact]
    public async Task The_user_list_is_for_admins_only_and_never_contains_password_material()
    {
        var admin = NewPerson("Admin"); var user = NewPerson();

        Assert.Equal(HttpStatusCode.Forbidden, (await user.Http.GetAsync("/api/admin/users")).StatusCode);
        var res = await admin.Http.GetAsync("/api/admin/users");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.DoesNotContain("password", await res.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    // ---- private collections ----

    [Fact]
    public async Task Friends_lists_and_likes_are_private_to_their_owner()
    {
        var me = NewPerson(); var other = NewPerson(); Befriend(me, other);

        Assert.Equal(HttpStatusCode.OK, (await me.Http.GetAsync($"/api/users/{me.Id}/friends")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await me.Http.GetAsync($"/api/users/{me.Id}/likes")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await other.Http.GetAsync($"/api/users/{me.Id}/friends")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await other.Http.GetAsync($"/api/users/{me.Id}/likes")).StatusCode);
    }

    [Fact]
    public async Task You_cannot_change_someone_elses_avatar()
    {
        var victim = NewPerson(); var attacker = NewPerson();
        using var form = new MultipartFormDataContent { { new ByteArrayContent([1, 2, 3]), "file", "a.png" } };

        Assert.Equal(HttpStatusCode.Forbidden, (await attacker.Http.PostAsync($"/api/users/{victim.Id}/avatar", form)).StatusCode);
    }

    // ---- blogs (resource-based) ----

    [Fact]
    public async Task New_blogs_belong_to_the_caller_whatever_the_body_claims()
    {
        var bob = NewPerson(); var alice = NewPerson();

        var res = await bob.Http.PostAsJsonAsync("/api/blogs", new { authorId = alice.Id, title = "hello", body = "<p>x</p>" });

        Assert.True(res.IsSuccessStatusCode);
        var id = (await Json(res)).GetProperty("id").GetInt32();
        Assert.Equal(bob.Id, InDb(db => db.Blogs.Single(b => b.Id == id).AuthorId));
    }

    [Fact]
    public async Task Only_the_author_edits_a_blog()
    {
        var author = NewPerson(); var stranger = NewPerson(); var admin = NewPerson("Admin"); var id = NewBlog(author);
        var edit = new { title = "edited", body = "<p>edited</p>" };

        Assert.Equal(HttpStatusCode.Forbidden, (await stranger.Http.PutAsJsonAsync($"/api/blogs/{id}", edit)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Http.PutAsJsonAsync($"/api/blogs/{id}", edit)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await author.Http.PutAsJsonAsync($"/api/blogs/{id}", edit)).StatusCode);
        Assert.Equal("edited", InDb(db => db.Blogs.Single(b => b.Id == id).Title));
        Assert.Equal(HttpStatusCode.NotFound, (await author.Http.PutAsJsonAsync("/api/blogs/2000000000", edit)).StatusCode);
    }

    [Fact]
    public async Task The_author_or_an_admin_deletes_a_blog_nobody_else_does()
    {
        var author = NewPerson(); var stranger = NewPerson(); var admin = NewPerson("Admin");
        var a = NewBlog(author); var b = NewBlog(author);

        Assert.Equal(HttpStatusCode.Forbidden, (await stranger.Http.DeleteAsync($"/api/blogs/{a}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await author.Http.DeleteAsync($"/api/blogs/{a}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Http.DeleteAsync($"/api/blogs/{b}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.Http.DeleteAsync($"/api/blogs/{b}")).StatusCode);
    }

    // ---- misc ----

    [Fact]
    public async Task Debug_endpoints_are_admin_only()
    {
        Assert.Equal(HttpStatusCode.Forbidden, (await NewPerson().Http.GetAsync("/api/debug/crash")).StatusCode);
    }
}
