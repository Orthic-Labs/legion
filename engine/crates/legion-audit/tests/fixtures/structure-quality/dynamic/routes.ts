export function reflectedHandler(): string {
  return "handled";
}

export async function loadRouteModule(name: string) {
  const module = await import(name);
  const handler = Reflect.get(module, "reflectedHandler");
  return handler;
}
