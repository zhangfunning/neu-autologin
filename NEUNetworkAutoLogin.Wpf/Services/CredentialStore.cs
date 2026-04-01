using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NEUNetworkAutoLogin.Models;

namespace NEUNetworkAutoLogin.Services;

public sealed class CredentialStore
{
    private readonly AppPaths _paths;
    private readonly AppLogger _logger;

    public CredentialStore(AppPaths paths, AppLogger logger)
    {
        _paths = paths;
        _logger = logger;
    }

    public CredentialModel Load()
    {
        try
        {
            if (!File.Exists(_paths.CredentialPath))
            {
                return new CredentialModel();
            }

            var raw = File.ReadAllText(_paths.CredentialPath, Encoding.UTF8);
            var record = JsonSerializer.Deserialize<CredentialRecord>(raw);
            if (record is null || string.IsNullOrWhiteSpace(record.Username) || string.IsNullOrWhiteSpace(record.EncryptedPassword))
            {
                return new CredentialModel();
            }

            var protectedBytes = Convert.FromBase64String(record.EncryptedPassword);
            var clearBytes = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
            var password = Encoding.UTF8.GetString(clearBytes);
            return new CredentialModel
            {
                Username = record.Username,
                Password = password
            };
        }
        catch (Exception ex)
        {
            _logger.Log($"Credential load failed: {ex.Message}");
            return new CredentialModel();
        }
    }

    public void Save(CredentialModel credential)
    {
        if (string.IsNullOrWhiteSpace(credential.Username) || string.IsNullOrWhiteSpace(credential.Password))
        {
            throw new InvalidOperationException("Username or password is empty.");
        }

        Directory.CreateDirectory(_paths.BaseDirectory);
        var clearBytes = Encoding.UTF8.GetBytes(credential.Password);
        var protectedBytes = ProtectedData.Protect(clearBytes, null, DataProtectionScope.CurrentUser);

        var record = new CredentialRecord
        {
            Username = credential.Username.Trim(),
            EncryptedPassword = Convert.ToBase64String(protectedBytes)
        };

        var json = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_paths.CredentialPath, json, Encoding.UTF8);
    }

    private sealed class CredentialRecord
    {
        public string Username { get; set; } = string.Empty;
        public string EncryptedPassword { get; set; } = string.Empty;
    }
}
