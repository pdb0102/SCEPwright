using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core;

public static class ScepCrypto {
    private const string BuiltInDll = "ScepTestClient.Crypto.BouncyCastle.dll";

    public static ScepClientResult Load(string? configured_dll_path, out IScepCrypto crypto, out string error) {
        string path;
        Assembly assembly;
        Type? impl_type;

        crypto = null!;
        error = string.Empty;

        path = string.IsNullOrWhiteSpace(configured_dll_path)
            ? Path.Combine(AppContext.BaseDirectory, BuiltInDll)
            : configured_dll_path!;

        if (!File.Exists(path)) {
            error = $"crypto provider DLL not found: {path}";
            return ScepClientResult.ProviderError;
        }

        try {
            assembly = string.IsNullOrWhiteSpace(configured_dll_path)
                ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path)
                : new ProviderLoadContext(path).LoadFromAssemblyPath(path);
            impl_type = assembly.GetTypes().FirstOrDefault(t =>
                typeof(IScepCrypto).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);
            if (impl_type is null) {
                error = $"no IScepCrypto implementation found in {Path.GetFileName(path)}";
                return ScepClientResult.ProviderError;
            }
            crypto = (IScepCrypto)Activator.CreateInstance(impl_type)!;
            return ScepClientResult.Ok;
        } catch (Exception ex) {
            error = $"failed to load crypto provider '{path}': {ex.Message}";
            return ScepClientResult.ProviderError;
        }
    }
}
