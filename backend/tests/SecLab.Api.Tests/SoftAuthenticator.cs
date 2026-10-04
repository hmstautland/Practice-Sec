using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecLab.Api.Tests;

/// <summary>
/// A software WebAuthn authenticator (ES256, "none" attestation) that builds the same JSON a browser's
/// PublicKeyCredential.toJSON() would produce. Lets the tests run a full registration/assertion ceremony.
/// </summary>
public sealed class SoftAuthenticator
{
    public const string RpId = "localhost";
    public const string Origin = "https://localhost:5173";

    public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);
    public uint SignCount { get; set; }

    public static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] FromB64(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
    }

    static string ClientData(string type, string challenge, string origin) =>
        JsonSerializer.Serialize(new { type, challenge, origin, crossOrigin = false });

    static byte[] BigEndian(uint v) => [(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];

    byte[] CoseKey()
    {
        var p = Key.ExportParameters(false);
        var w = new CborWriter();
        w.WriteStartMap(5);
        w.WriteInt32(1); w.WriteInt32(2);           // kty: EC2
        w.WriteInt32(3); w.WriteInt32(-7);          // alg: ES256
        w.WriteInt32(-1); w.WriteInt32(1);          // crv: P-256
        w.WriteInt32(-2); w.WriteByteString(p.Q.X!);
        w.WriteInt32(-3); w.WriteByteString(p.Q.Y!);
        w.WriteEndMap();
        return w.Encode();
    }

    /// <summary>Registration response for the challenge the server issued. Flags: UP + AT (+ UV unless disabled).</summary>
    public object Register(string challenge, string origin = Origin, string rpId = RpId, bool userVerified = true)
    {
        var flags = (byte)(0x01 | 0x40 | (userVerified ? 0x04 : 0));
        var authData = SHA256.HashData(Encoding.UTF8.GetBytes(rpId))
            .Concat([flags]).Concat(BigEndian(SignCount)).Concat(new byte[16])       // rpIdHash, flags, counter, AAGUID
            .Concat([(byte)(CredentialId.Length >> 8), (byte)CredentialId.Length]).Concat(CredentialId).Concat(CoseKey())
            .ToArray();

        var att = new CborWriter();
        att.WriteStartMap(3);
        att.WriteTextString("fmt"); att.WriteTextString("none");
        att.WriteTextString("attStmt"); att.WriteStartMap(0); att.WriteEndMap();
        att.WriteTextString("authData"); att.WriteByteString(authData);
        att.WriteEndMap();

        return new
        {
            id = B64(CredentialId), rawId = B64(CredentialId), type = "public-key",
            response = new
            {
                attestationObject = B64(att.Encode()),
                clientDataJSON = B64(Encoding.UTF8.GetBytes(ClientData("webauthn.create", challenge, origin))),
            },
            clientExtensionResults = new { },
        };
    }

    /// <summary>Assertion response. Increments the counter unless one is given; signs with <paramref name="signWith"/> or the real key.</summary>
    public object Assert(string challenge, string origin = Origin, string rpId = RpId, uint? counter = null,
        ECDsa? signWith = null, bool userVerified = true)
    {
        SignCount = counter ?? SignCount + 1;
        var flags = (byte)(0x01 | (userVerified ? 0x04 : 0));
        var authData = SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).Concat([flags]).Concat(BigEndian(SignCount)).ToArray();
        var clientData = Encoding.UTF8.GetBytes(ClientData("webauthn.get", challenge, origin));
        var signed = authData.Concat(SHA256.HashData(clientData)).ToArray();
        var signature = (signWith ?? Key).SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        return new
        {
            id = B64(CredentialId), rawId = B64(CredentialId), type = "public-key",
            response = new { authenticatorData = B64(authData), clientDataJSON = B64(clientData), signature = B64(signature), userHandle = (string?)null },
            clientExtensionResults = new { },
        };
    }
}
