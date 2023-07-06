async function populate() {

    const requestURL = './get_id_info.php';
    const request = new Request(requestURL);
  
    const response = await fetch(request);
    const raw = await response.text();
    const data = JSON.parse(raw) ;
    
    var body = document.getElementById("container");
    var elem = document.createElement("h3");
    elem.innerHTML = "ID : " + data.id;
    body.appendChild(elem);

    elem = document.createElement("h5");
    elem.innerHTML = "Name : " + data.name;
    body.appendChild(elem);

    elem = document.createElement("h5");
    elem.innerHTML = "Age : " + data.age;
    body.appendChild(elem);
}
  
populate();