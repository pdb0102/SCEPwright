using System.IO;
using ScepTestClient.Core.Protocol;
using ScepTestClient.Core.Storage;
using ScepTestClient.Core.Testing;

namespace ScepTestClient.Tests;

public sealed class SecurityOpinionTests {
    [Fact]
    public void Digest_Postures() {
        Assert.Equal(AlgorithmPosture.MustNot, SecurityOpinion.ClassifyDigest("MD5"));
        Assert.Equal(AlgorithmPosture.LegacyWeak, SecurityOpinion.ClassifyDigest("SHA-1"));
        Assert.Equal(AlgorithmPosture.Modern, SecurityOpinion.ClassifyDigest("SHA-256"));
    }

    [Fact]
    public void Rsa_BelowThreshold_IsWeak() {
        OpinionThresholds thresholds;

        thresholds = new OpinionThresholds { MinRsaKeyBits = 2048 };
        Assert.Equal(AlgorithmPosture.LegacyWeak, SecurityOpinion.ClassifyRsa(1024, thresholds));
        Assert.Equal(AlgorithmPosture.Modern, SecurityOpinion.ClassifyRsa(2048, thresholds));
    }

    [Fact]
    public void Config_MinRsaKeyBits_RoundTrips() {
        string root;
        ClientConfig config;
        ClientConfig reloaded;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        config = new ClientConfig { MinRsaKeyBits = 3072 };
        config.Save(root);
        reloaded = ClientConfig.Load(root);
        Assert.Equal(3072, reloaded.MinRsaKeyBits);
    }

    [Fact]
    public void Suggest_EmitsCommandsForAdvertisedAlgorithms() {
        ScepCapabilities caps;
        System.Collections.Generic.IReadOnlyList<string> lines;

        caps = ScepCapabilities.Parse("SHA-256\nAES\n");
        lines = ServerSuggest.For("testhost", caps);
        Assert.Contains(lines, l => l.Contains("--digest SHA-256") && l.Contains("--cipher AES-128-CBC"));
    }
}
