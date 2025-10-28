        

    const entrar = document.querySelector('.entrar');
    const esquecer = document.getElementById('esqueceusenha');
    const botao = document.querySelector('#caseform5 input');

    entrar.addEventListener('mouseenter', () => {botao.style.backgroundImage = "var(--degradecinza)"});
    entrar.addEventListener('mouseleave', () => {botao.style.backgroundImage = "var(--degrade)"});   
    esquecer.addEventListener('mouseenter', () => {botao.style.backgroundImage = "var(--degradecinza)"});
    esquecer.addEventListener('mouseleave', () => {botao.style.backgroundImage = "var(--degrade)"});


function Menu() {
    const root = document.documentElement;
    const valor = getComputedStyle(root).getPropertyValue('--visivel').trim();
    if (valor === 'block') {
        root.style.setProperty('--visivel', 'none');
        headerpos.style.justifyContent = 'space-between'
    }
    else {

        root.style.setProperty('--visivel', 'block');
        headerpos.style.justifyContent = 'center';
    }
}


