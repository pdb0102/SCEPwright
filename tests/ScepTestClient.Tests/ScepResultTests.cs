using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public class ScepResultTests {
    [Fact]
    public void Ok_carries_value_and_no_error() {
        ScepResult<int> result;

        result = ScepResult<int>.Ok(42);

        Assert.Equal(ScepClientResult.Ok, result.Status);
        Assert.Equal(42, result.Value);
        Assert.Equal(string.Empty, result.Error);
        Assert.True(result.IsOk);
    }

    [Fact]
    public void Fail_carries_status_and_message() {
        ScepResult<int> result;

        result = ScepResult<int>.Fail(ScepClientResult.NetworkError, "boom");

        Assert.Equal(ScepClientResult.NetworkError, result.Status);
        Assert.Equal("boom", result.Error);
        Assert.False(result.IsOk);
    }

    [Fact]
    public void Scep_enum_values_match_rfc8894() {
        Assert.Equal(19, (int)MessageType.PkcsReq);
        Assert.Equal(17, (int)MessageType.RenewalReq);
        Assert.Equal(20, (int)MessageType.CertPoll);
        Assert.Equal(3, (int)MessageType.CertRep);
        Assert.Equal(2, (int)PkiStatus.Failure);
        Assert.Equal(3, (int)PkiStatus.Pending);
        Assert.Equal(4, (int)FailInfo.BadCertId);
    }
}
