#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["src/Services/MksStoreEnterprise.Client.API/MksStoreEnterprise.Client.API.csproj", "src/Services/MksStoreEnterprise.Client.API/"]
RUN dotnet restore "src/Services/MksStoreEnterprise.Client.API/MksStoreEnterprise.Client.API.csproj"
COPY . .
WORKDIR "/src/src/Services/MksStoreEnterprise.Client.API"
RUN dotnet build "MksStoreEnterprise.Client.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "MksStoreEnterprise.Client.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MksStoreEnterprise.Client.API.dll"]