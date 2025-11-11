const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));


fetch("http://localhost:3000/create-order", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ amount: 159700 })
})
  .then(res => res.json())
  .then(data => {
    console.log("✅ Server Response:");
    console.log(data);
  })
  .catch(err => {
    console.error("❌ Error occurred:", err.message);
  });
