using System;
using System.Collections.Generic;
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
            Type[] candidates;
            ScepClientResult select_result;

            assembly = string.IsNullOrWhiteSpace(configured_dll_path)
                ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path)
                : new ProviderLoadContext(path).LoadFromAssemblyPath(path);

            try {
                candidates = assembly.GetTypes();
            } catch (ReflectionTypeLoadException ex) {
                error = $"failed to inspect provider '{Path.GetFileName(path)}': {ex.LoaderExceptions.FirstOrDefault()?.Message ?? ex.Message}";
                return ScepClientResult.ProviderError;
            }

            select_result = SelectImplType(candidates, Path.GetFileName(path), out impl_type, out error);
            if (select_result != ScepClientResult.Ok) {
                return select_result;
            }

            crypto = (IScepCrypto)Activator.CreateInstance(impl_type!)!;
            return ScepClientResult.Ok;
        } catch (Exception ex) {
            error = $"failed to load crypto provider '{path}': {ex.Message}";
            return ScepClientResult.ProviderError;
        }
    }

    // Deterministically pick the single concrete IScepCrypto implementation among the
    // candidate types. Zero or more-than-one is an error (never first-wins), so an
    // ambiguous provider assembly is rejected with a clear message instead of silently
    // binding to whichever type the reflection enumeration happened to return first.
    internal static ScepClientResult SelectImplType(Type[] candidates, string file, out Type? impl, out string error) {
        List<Type> impls;

        impl = null;
        error = string.Empty;

        impls = candidates
            .Where(t => typeof(IScepCrypto).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface)
            .ToList();

        if (impls.Count == 0) {
            error = $"no IScepCrypto implementation found in {file}";
            return ScepClientResult.ProviderError;
        }
        if (impls.Count > 1) {
            error = $"multiple IScepCrypto implementations found in {file} ({impls.Count})";
            return ScepClientResult.ProviderError;
        }

        impl = impls[0];
        return ScepClientResult.Ok;
    }
}
