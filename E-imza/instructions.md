# Build
dotnet build SigningService.sln

# Run tests
dotnet test SigningService.Tests

# Run examples
dotnet run --project SigningService

# For clean up
dotnet clean SigningService.sln
dotnet clean SigningService.sln -c Releases
