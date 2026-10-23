export function Button(props: { label: string }) {
  console.log(props.label);
  return <button>{props.label}</button>;
}
