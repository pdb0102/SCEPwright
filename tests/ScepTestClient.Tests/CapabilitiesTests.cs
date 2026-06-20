using ScepTestClient.Core.Protocol;
using Xunit;

namespace ScepTestClient.Tests;

public class CapabilitiesTests {
    [Fact]
    public void Parses_keyword_list() {
        ScepCapabilities caps;

        caps = ScepCapabilities.Parse("POSTPKIOperation\r\nSHA-256\nAES\nRenewal\n");

        Assert.True(caps.PostPkiOperation);
        Assert.True(caps.Sha256);
        Assert.True(caps.Aes);
        Assert.True(caps.Renewal);
        Assert.False(caps.Sha512);
        Assert.False(caps.Des3);
    }

    [Fact]
    public void Unknown_keywords_recorded_not_error() {
        ScepCapabilities caps;

        caps = ScepCapabilities.Parse("SHA-256\nFANCYTHING\n");

        Assert.True(caps.Sha256);
        Assert.Contains("FANCYTHING", caps.Unknown);
    }
}
