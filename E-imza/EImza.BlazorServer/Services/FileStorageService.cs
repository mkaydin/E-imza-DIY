using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.Extensions.Options;

namespace EImza.BlazorServer.Services;

public class FileStorageOptions
{
    public string TempPath { get; set; } = Path.GetTempPath();
    public int MaxAgeMinutes { get; set; } = 60;
    public long MaxFileSizeBytes { get; set; } = 50 * 1024 * 1024; // 50MB
}

public class StoredFileInfo
{
    public string FileId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public long Size { get; set; }
    public DateTime CreatedAt { get; set; }
    public string FilePath { get; set; } = string.Empty;
}

public class FileStorageService
{
    private readonly FileStorageOptions _options;
    private readonly ILogger<FileStorageService> _logger;
    private readonly Dictionary<string, StoredFileInfo> _fileIndex = new();
    private readonly SemaphoreSlim _lock = new(1, 1);

    public FileStorageService(IOptions<FileStorageOptions> options, ILogger<FileStorageService> logger)
    {
        _options = options.Value;
        _logger = logger;

        // Ensure temp directory exists
        if (!Directory.Exists(_options.TempPath))
        {
            Directory.CreateDirectory(_options.TempPath);
        }
    }

    public async Task<string> StoreFileAsync(IBrowserFile file)
    {
        if (file.Size > _options.MaxFileSizeBytes)
        {
            throw new InvalidOperationException(
                $"File too large. Maximum size is {_options.MaxFileSizeBytes / (1024 * 1024)}MB.");
        }

        var fileId = Guid.NewGuid().ToString();
        var filePath = Path.Combine(_options.TempPath, $"{fileId}_{file.Name}");

        await using var fileStream = file.OpenReadStream(_options.MaxFileSizeBytes);
        await using var fileStream2 = new FileStream(filePath, FileMode.Create);
        await fileStream.CopyToAsync(fileStream2);

        var fileInfo = new StoredFileInfo
        {
            FileId = fileId,
            Name = file.Name,
            ContentType = file.ContentType,
            Size = file.Size,
            CreatedAt = DateTime.UtcNow,
            FilePath = filePath
        };

        await _lock.WaitAsync();
        try
        {
            _fileIndex[fileId] = fileInfo;
        }
        finally
        {
            _lock.Release();
        }

        _logger.LogInformation("File stored: {FileId} - {FileName}", fileId, file.Name);

        return fileId;
    }

    public async Task<string> StoreFileAsync(byte[] content, string fileName)
    {
        if (content.Length > _options.MaxFileSizeBytes)
        {
            throw new InvalidOperationException(
                $"File too large. Maximum size is {_options.MaxFileSizeBytes / (1024 * 1024)}MB.");
        }

        var fileId = Guid.NewGuid().ToString();
        var filePath = Path.Combine(_options.TempPath, $"{fileId}_{fileName}");

        await File.WriteAllBytesAsync(filePath, content);

        var fileInfo = new StoredFileInfo
        {
            FileId = fileId,
            Name = fileName,
            ContentType = "application/octet-stream",
            Size = content.Length,
            CreatedAt = DateTime.UtcNow,
            FilePath = filePath
        };

        await _lock.WaitAsync();
        try
        {
            _fileIndex[fileId] = fileInfo;
        }
        finally
        {
            _lock.Release();
        }

        _logger.LogInformation("File stored: {FileId} - {FileName}", fileId, fileName);

        return fileId;
    }

    public async Task<byte[]?> GetFileAsync(string fileId, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            // First try to find in index
            if (_fileIndex.TryGetValue(fileId, out var fileInfo))
            {
                if (File.Exists(fileInfo.FilePath))
                {
                    return await File.ReadAllBytesAsync(fileInfo.FilePath, cancellationToken);
                }
            }

            // Fallback: search for file on disk using the naming pattern
            var files = Directory.GetFiles(_options.TempPath, $"{fileId}_*");
            if (files.Length > 0)
            {
                var filePath = files[0];
                var fileName = Path.GetFileName(filePath).Substring(fileId.Length + 1);

                // Rebuild the file info
                var rebuiltInfo = new StoredFileInfo
                {
                    FileId = fileId,
                    Name = fileName,
                    ContentType = "application/octet-stream",
                    Size = new FileInfo(filePath).Length,
                    CreatedAt = File.GetCreationTimeUtc(filePath),
                    FilePath = filePath
                };

                // Add back to index
                _fileIndex[fileId] = rebuiltInfo;

                return await File.ReadAllBytesAsync(filePath, cancellationToken);
            }

            return null;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<StoredFileInfo?> GetFileInfoAsync(string fileId, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            // First try to find in index
            if (_fileIndex.TryGetValue(fileId, out var fileInfo))
            {
                return fileInfo;
            }

            // Fallback: search for file on disk using the naming pattern
            var files = Directory.GetFiles(_options.TempPath, $"{fileId}_*");
            if (files.Length > 0)
            {
                var filePath = files[0];
                var fileName = Path.GetFileName(filePath).Substring(fileId.Length + 1);
                var fileInfo2 = new FileInfo(filePath);

                var rebuiltInfo = new StoredFileInfo
                {
                    FileId = fileId,
                    Name = fileName,
                    ContentType = "application/octet-stream",
                    Size = fileInfo2.Length,
                    CreatedAt = fileInfo2.CreationTimeUtc,
                    FilePath = filePath
                };

                // Add back to index
                _fileIndex[fileId] = rebuiltInfo;

                return rebuiltInfo;
            }

            return null;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task CleanupOldFilesAsync(TimeSpan maxAge)
    {
        await _lock.WaitAsync();
        try
        {
            var now = DateTime.UtcNow;
            var expiredFiles = _fileIndex
                .Where(kvp => now - kvp.Value.CreatedAt > maxAge)
                .ToList();

            foreach (var (fileId, fileInfo) in expiredFiles)
            {
                try
                {
                    if (File.Exists(fileInfo.FilePath))
                    {
                        File.Delete(fileInfo.FilePath);
                        _logger.LogInformation("Deleted expired file: {FileId}", fileId);
                    }
                    _fileIndex.Remove(fileId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error deleting file: {FileId}", fileId);
                }
            }
        }
        finally
        {
            _lock.Release();
        }
    }
}
