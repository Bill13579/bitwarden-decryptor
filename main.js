import './style.css'
import { decrypt_js } from './hello-wasm/pkg/hello_wasm'

async function openFile() {
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = '.json';
  fileInput.onchange = async (event) => {
    const file = event.target.files[0];
    document.getElementById("open-file-name").innerText = file.name;
    if (file) {
      const text = await file.text();
      window.bitwardenData = JSON.parse(text);
    }
  };
  fileInput.click();
}

async function gridify(data) {
  let folderIdMap = {};
  for (let folder of data.folders) {
    folderIdMap[folder.id] = folder.name;
  }
  folderIdMap[null] = "no folder";

  let tbody = document.getElementById("tbody");
  tbody.innerHTML = "";
  for (let item of data.items) {
    let tr = document.createElement("tr");
    let generate = s => {
      let g = document.createElement("td");
      g.innerText = s;
      return g;
    };
    for (let val of [item.id.toString().substring(0, 8), folderIdMap[item.folderId], item.name, item.notes, item.favorite ? "⭐" : "  ", item.login]) {
      let valstr;
      if (typeof val === 'string' || val instanceof String) {
        valstr = val.toString();
      } else {
        valstr = JSON.stringify(val, null, 2);
      }
      tr.appendChild(generate(valstr));
    }
    tbody.appendChild(tr);
  }
}

async function decryptData() {
  const password = document.getElementById('password').value;
  if (window.bitwardenData) {
    try {
      const decryptedData = await decryptWithPassword(password, window.bitwardenData);
      let decryptedDataJson = JSON.parse(decryptedData);
      gridify(decryptedDataJson);
      document.getElementById('data').value = JSON.stringify(decryptedDataJson, null, 4);
    } catch (error) {
      console.error(error);
    }
  }
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join(' ');
}

async function decryptWithPassword(password, bitwardenData) {
  let result = decrypt_js(password, bitwardenData.salt, bitwardenData.kdfIterations, bitwardenData.data);
  document.getElementById("decrypt-data-error").innerText = result.error;
  return result.data;
}

function base64Decode(encoded) {
  const decoded = atob(encoded);
  const uint8Array = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; ++i) {
      uint8Array[i] = decoded.charCodeAt(i);
  }
  return uint8Array;
}

document.getElementById("open-file-btn").addEventListener("click", openFile);
document.getElementById("decrypt-data-btn").addEventListener("click", decryptData);

