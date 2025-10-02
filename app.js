async function checkEligibility(){
  const res = await fetch('/api/check');
  const data = await res.json();
  renderCard(data);
}

function renderCard(data){
  const wrapper = document.getElementById('eligibilityCardWrapper');
  wrapper.innerHTML = '';

  const card = document.createElement('div');
  card.className = 'eligibility-card';
  card.id = 'eligibilityCard';

  const avatar = document.createElement('img');
  avatar.className = 'avatar';
  avatar.src = data.avatar || 'https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png';

  const info = document.createElement('div');
  info.className = 'info';

  const uname = document.createElement('div');
  uname.className = 'username';
  uname.innerText = data.username;

  const badge = document.createElement('div');
  badge.innerHTML = data.eligible ? `<span class="badge">Rialo Verified ✅</span>` : '';

  const status = document.createElement('div');
  status.className = 'status';
  status.innerHTML = data.eligible ? "You mentioned <b>rialo</b> 🎉" : "Not eligible";

  const qr = document.createElement('img');
  qr.src = `https://api.qrserver.com/v1/create-qr-code/?size=100x100&data=https://twitter.com/${data.username}`;
  qr.style.marginTop = '12px';

  info.appendChild(uname);
  info.appendChild(badge);
  info.appendChild(status);
  info.appendChild(qr);

  card.appendChild(avatar);
  card.appendChild(info);

  wrapper.appendChild(card);
}

async function downloadCard(){
  const card = document.getElementById('eligibilityCard');
  if(!card) return alert("No card yet!");
  const canvas = await html2canvas(card);
  const link = document.createElement('a');
  link.download = 'eligibility-card.png';
  link.href = canvas.toDataURL();
  link.click();
}

checkEligibility();
