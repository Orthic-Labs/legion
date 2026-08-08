static class Negative { public static void Leak()=>new FileStream("x",FileMode.Open); }
