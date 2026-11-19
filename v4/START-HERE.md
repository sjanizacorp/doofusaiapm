# DoofusAI SPM v4

Authored by Aniza Inc.

1. Extract the ZIP to a folder you can find later. Open a Terminal in that folder.
2. Check that `python3 --version` reports Python 3.13 on Linux or macOS.
3. Type `./install.sh`. At the directory prompt, press Enter for the displayed default or type a dedicated installation path. Then use the start command printed by the installer. For unattended installation, run `./install.sh --installdir "/path/to/DoofusAI"`.
4. Follow the Administration Manual to create your first local username/password account. Open `http://127.0.0.1:8000` on the same computer and sign in.
5. For a custom directory, pass `--installdir "/path/to/DoofusAI"` to the scripts in this extracted folder, or run the installed controls in that directory’s bin folder. Use `./status.sh` to check the service, `./stop.sh` to stop it, and `./uninstall.sh` to remove the runtime. Uninstall retains local data, logs, and configuration.

Begin with the three PDFs in `manuals/`. The Configuration Manual covers ports, platform credentials, agents, and HTTPS deployment.
