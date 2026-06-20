using System.Reflection;
using System.Runtime.Loader;

namespace ScepTestClient.Core;

internal sealed class ProviderLoadContext : AssemblyLoadContext {
    private readonly AssemblyDependencyResolver _resolver;

    public ProviderLoadContext(string provider_path) : base(isCollectible: true) {
        _resolver = new AssemblyDependencyResolver(provider_path);
    }

    protected override Assembly? Load(AssemblyName name) {
        string? path;

        // Share the contract assembly with the host so IScepCrypto keeps one Type identity.
        if (name.Name == "ScepTestClient.CryptoApi") {
            return null;
        }

        path = _resolver.ResolveAssemblyToPath(name);
        return path is null ? null : LoadFromAssemblyPath(path);
    }
}
