using System;
using System.IO;
using System.Threading;
using System.Security.Principal;
using System.Diagnostics;

public class AntiRansomwareProducao
{
    // --- Configurações CRÍTICAS ---
    // Diretório de teste informado pelo usuário
    private const string DIRETORIO_MONITORADO = @"C:\DIRETORIOTESTE";

    // Nomes dos arquivos isca (honeypots)
    private static readonly string[] ARQUIVOS_HONEYPOT =
    {
        "DADOS_CONFIDENCIAIS_NAO_ABRIR.doc",
        "CHAVES_PRIVADAS_DE_TESTE.key",
        "Senhas_Root_FALSAS.txt"
    };

    // Lista de processos suspeitos (exemplo)
    private static readonly string[] PROCESSOS_SUSPEITOS =
    {
        "encryptor.exe",
        "malware.exe",
        "ransomer.exe"
    };

    // Mantém referência ao watcher para evitar disposal/garbage collection
    private static FileSystemWatcher watcher;

    public static void Main(string[] args)
    {
        Console.WriteLine("--- Anti-Ransomware Honeypot V1.1 (Teste) ---");

        if (!IsAdministrator())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("ALERTA: Execute como Administrador para ações que alteram adaptadores e permissões.");
            Console.ResetColor();
            return;
        }

        if (!PreparaAmbiente())
        {
            Console.WriteLine("Erro ao preparar o ambiente. Verifique permissões.");
            return;
        }

        MonitoraDiretorio();

        Console.WriteLine("\nSistema de monitoramento ATIVO. Pressione Enter para encerrar.");
        Console.ReadLine();

        // Opcional: Dispose ao encerrar
        watcher?.Dispose();
    }

    private static bool IsAdministrator()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool PreparaAmbiente()
    {
        try
        {
            if (!Directory.Exists(DIRETORIO_MONITORADO))
            {
                Directory.CreateDirectory(DIRETORIO_MONITORADO);
            }

            foreach (var nomeArquivo in ARQUIVOS_HONEYPOT)
            {
                string caminhoCompleto = Path.Combine(DIRETORIO_MONITORADO, nomeArquivo);
                if (!File.Exists(caminhoCompleto))
                {
                    File.WriteAllText(caminhoCompleto, $"HONEYPOT ATIVO. Conteúdo falso. Nome: {nomeArquivo}");
                }
            }
            Console.WriteLine($"Ambiente preparado em: {DIRETORIO_MONITORADO}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exceção durante a preparação: {ex.Message}");
            return false;
        }
    }

    private static void MonitoraDiretorio()
    {
        watcher = new FileSystemWatcher(DIRETORIO_MONITORADO)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Security | NotifyFilters.Size,
            Filter = "*.*",
            IncludeSubdirectories = true,
            EnableRaisingEvents = true
        };

        // Aumente se necessário (em bytes)
        watcher.InternalBufferSize = 64 * 1024;

        watcher.Created += OnHoneypotAcessado_CreatedOrChanged;
        watcher.Changed += OnHoneypotAcessado_CreatedOrChanged;
        watcher.Deleted += OnHoneypotAcessado_CreatedOrChanged;
        watcher.Renamed += OnHoneypotAcessado_Renamed;
        watcher.Error += OnWatcherError;

        Console.WriteLine($"Iniciando monitoramento em '{DIRETORIO_MONITORADO}' (subpastas incl.)...");
    }

    private static void OnHoneypotAcessado_CreatedOrChanged(object source, FileSystemEventArgs e)
    {
        VerificaEAcionaHoneypot(e.FullPath, e.ChangeType.ToString());
    }

    private static void OnHoneypotAcessado_Renamed(object source, RenamedEventArgs e)
    {
        VerificaEAcionaHoneypot(e.FullPath, $"Renamed (de: {e.OldName})");
    }

    private static void VerificaEAcionaHoneypot(string fullPath, string descricaoEvento)
    {
        try
        {
            string nomeArquivo = Path.GetFileName(fullPath);
            // Log de depuração simples
            Console.WriteLine($"Evento: {descricaoEvento} -> {fullPath}");

            if (Array.Exists(ARQUIVOS_HONEYPOT, element => element.Equals(nomeArquivo, StringComparison.OrdinalIgnoreCase)))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n!!! AMEAÇA DETECTADA NO HONEYPOT !!!");
                Console.WriteLine($"O arquivo '{nomeArquivo}' sofreu: {descricaoEvento} (caminho: {fullPath})");
                Console.WriteLine("EXECUTANDO PROTOCOLOS DE BLOQUEIO DE INCIDENTE...");
                Console.ResetColor();

                AcaoDeBloqueioUrgenteReal();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao processar evento do honeypot: {ex.Message}");
        }
    }

    private static void OnWatcherError(object sender, ErrorEventArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("ALERTA: FileSystemWatcher reportou um erro: " + e.GetException()?.Message);
        Console.WriteLine("Considere aumentar InternalBufferSize ou reduzir área monitorada.");
        Console.ResetColor();
    }

    private static void AcaoDeBloqueioUrgenteReal()
    {
        Console.WriteLine("- EXECUTANDO: Tentando desativar todas as interfaces de rede...");
        try
        {
            ExecutePowerShellCommand("Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} | Disable-NetAdapter -Confirm:$false");
            Console.WriteLine("-> SUCESSO: Rede Desativada.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"-> FALHA na desativação de rede: {ex.Message}");
        }

        Console.WriteLine("- EXECUTANDO: Encerrando processos de Ransomware conhecidos...");
        foreach (var processo in PROCESSOS_SUSPEITOS)
        {
            try
            {
                ExecutePowerShellCommand($"Stop-Process -Name '{processo}' -Force -ErrorAction SilentlyContinue");
                Console.WriteLine($"-> PROCESSO ENCERRADO TENTADO: {processo}");
            }
            catch { }
        }
        Console.WriteLine("-> SUCESSO: Verificação de processos concluída.");

        Console.WriteLine("- EXECUTANDO: Bloqueando permissões de escrita no diretório monitorado...");
        try
        {
            ExecutePowerShellCommand($"icacls \"{DIRETORIO_MONITORADO}\" /deny *S-1-1-0:(OI)(CI)W /T");
            Console.WriteLine("-> SUCESSO: Permissões de escrita bloqueadas na área crítica.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"-> FALHA ao bloquear permissões: {ex.Message}");
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n!!! INTERVENÇÃO COMPLETA: O SISTEMA ESTÁ ISOLADO. !!!");
        Console.WriteLine("A equipe de TI DEVE ser notificada Imediatamente para quarentena completa e análise forense.");
        Console.ResetColor();
    }

    private static void ExecutePowerShellCommand(string command)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-Command \"{command}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            }
        };
        process.Start();
        process.WaitForExit();
    }
}
