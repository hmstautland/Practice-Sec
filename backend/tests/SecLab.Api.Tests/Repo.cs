namespace SecLab.Api.Tests;

/// <summary>Finds the repository root (the folder that has docs/ and backend/) so tests can check files-as-configuration.</summary>
public static class Repo
{
    public static string Root { get; } = Find();

    static string Find()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, "docs")) && Directory.Exists(Path.Combine(dir.FullName, "backend")))
                return dir.FullName;
        throw new DirectoryNotFoundException("repository root not found");
    }

    public static string Path_(string relative) => Path.Combine(Root, relative);
}
