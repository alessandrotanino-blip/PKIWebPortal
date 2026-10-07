namespace PkiPortal.Models;

public class AdminConfig
{
    public List<string> AllowedGroups { get; set; } = new() { "BUILTIN\\Administrators" };
    public List<string> AllowedUsers { get; set; } = new();
}
