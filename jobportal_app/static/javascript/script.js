
function showForm(){
  document.getElementById("myform").style.display = "block";
}
function showForm2(){
  document.getElementById("myform2").style.display = "block";
}

function toggleMenu() {
    const menu = document.getElementById("menu");
    menu.classList.toggle("show");
}

document.addEventListener('DOMContentLoaded', function() {
    const input1 = document.getElementById('input1');
    const input2 = document.getElementById('input2');
    const input3 = document.getElementById('input3');

    input1.addEventListener('input', function() {
        if (input1.value.trim() !== '') {
            // If input1 has a value, disable or make others read-only
            input2.disabled = true; // or input2.readOnly = true;
            input3.disabled = true; // or input3.readOnly = true;
        }
        else{
            input2.disabled = false;
            input3.disabled = false;
        }
    });
});
