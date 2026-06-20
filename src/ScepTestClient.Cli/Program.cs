using ScepTestClient.Cli;
using ScepTestClient.Core.Storage;

string? data_dir_flag;
string root;

data_dir_flag = GetFlag(args, "--data-dir");
root = DataRoot.Resolve(data_dir_flag);
return CommandRouter.Run(args, root, System.Console.Out);

static string? GetFlag(string[] args, string name) {
    for (int i = 0; i < args.Length - 1; i++) {
        if (args[i] == name) return args[i + 1];
    }
    return null;
}
