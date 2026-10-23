import { component$, useSignal, useTask$ } from "@builder.io/qwik";

export const Counter = component$(() => {
  const count = useSignal(0);
  const cache = useTask$(() => new Map());
  debugger;
  return <button onClick$={() => count.value++}>{count.value}</button>;
});
