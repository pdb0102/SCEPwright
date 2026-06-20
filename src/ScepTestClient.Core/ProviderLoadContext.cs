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

        // Returning null here forces the contract assembly to resolve to the host's
        // already-loaded copy (via AssemblyLoadContext.Default) instead of being loaded a
        // second time into this collectible ALC. In .NET, Type identity = assembly + the
        // ALC that loaded it, so a second copy would yield a *distinct* IScepCrypto /
        // IScepKey Type that fails (InvalidCastException) when cast across the boundary.
        // Sharing the host's copy guarantees a single Type identity for the contract types,
        // letting a path-loaded provider's IScepCrypto/IScepKey instances flow back to the
        // host transparently.
        if (name.Name == "ScepTestClient.CryptoApi") {
            return null;
        }

        path = _resolver.ResolveAssemblyToPath(name);
        return path is null ? null : LoadFromAssemblyPath(path);
    }
}
