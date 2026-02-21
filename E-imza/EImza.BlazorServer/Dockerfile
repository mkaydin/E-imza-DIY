# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy project files
COPY ["EImza.BlazorServer/EImza.BlazorServer.csproj", "EImza.BlazorServer/"]
COPY ["SigningService/SigningService.csproj", "SigningService/"]

# Restore dependencies
RUN dotnet restore "EImza.BlazorServer/EImza.BlazorServer.csproj"

# Copy all project files
COPY EImza.BlazorServer/ EImza.BlazorServer/
COPY SigningService/ SigningService/

# Build the project
WORKDIR "/src/EImza.BlazorServer"
RUN dotnet build "EImza.BlazorServer.csproj" -c Release -o /app/build

# Publish the project
RUN dotnet publish "EImza.BlazorServer.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app

# Create uploads directory
RUN mkdir -p /var/lib/eimza/uploads && \
    chmod 755 /var/lib/eimza/uploads

# Copy published app
COPY --from=build /app/publish .

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV FileStorage__TempPath=/var/lib/eimza/uploads
ENV FileStorage__MaxAgeMinutes=60
ENV FileStorage__MaxFileSizeBytes=52428800

# Expose port
EXPOSE 8080

# Run the app
ENTRYPOINT ["dotnet", "EImza.BlazorServer.dll"]
