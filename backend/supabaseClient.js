import supabase from "./backend/supabaseClient.js";

// Ambil semua user
app.get("/users", async (req, res) => {
  const { data, error } = await supabase.auth.admin.listUsers();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
