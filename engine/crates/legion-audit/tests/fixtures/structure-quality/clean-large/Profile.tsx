import { useState } from "react";

export function ProfileCard(props: { name: string; bio: string }) {
  const [expanded, setExpanded] = useState(false);
  const heading = props.name;
  const body = props.bio;
  const row1 = heading;
  const row2 = body;
  const row3 = heading;
  const row4 = body;
  const row5 = heading;
  const row6 = body;
  const row7 = heading;
  const row8 = body;
  const row9 = heading;
  const row10 = body;
  const row11 = heading;
  const row12 = body;
  const row13 = heading;
  const row14 = body;
  const row15 = heading;
  const row16 = body;
  const row17 = heading;
  const row18 = body;
  const row19 = heading;
  const row20 = body;
  const row21 = heading;
  const row22 = body;
  const row23 = heading;
  const row24 = body;
  const row25 = heading;
  const row26 = body;
  const rows = [row1, row2, row3, row4, row5, row6, row7, row8, row9, row10];
  const more = [row11, row12, row13, row14, row15, row16, row17, row18];
  const tail = [row19, row20, row21, row22, row23, row24, row25, row26];
  const toggle = () => setExpanded(!expanded);
  return { rows, more, tail, toggle, expanded };
}
