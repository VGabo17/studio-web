export async function pingMinecraftServer(ip) {
  if (!ip) throw new Error("Debes ingresar una IP válida");
  
  const response = await fetch(`https://api.mcsrvstat.us/2/${encodeURIComponent(ip)}`);
  if (!response.ok) throw new Error("No se pudo contactar con la API");
  
  return await response.json();
}
