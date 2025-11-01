// static/script.js

// --- MAP INITIALIZATION ---
const map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
}).addTo(map);

const markers = L.markerClusterGroup();
map.addLayer(markers);


// --- DOM ELEMENT SELECTORS ---
const drilldownLogFeed = document.getElementById('drilldown-log-feed');
const drilldownTitle = document.getElementById('drilldown-title');
const flaggedLogFeed = document.getElementById('flagged-log-feed');
const liveLogFeed = document.getElementById('live-log-feed');
const contextMenu = document.getElementById('custom-context-menu');
const menuFlagIp = document.getElementById('menu-flag-ip');
const menuCheckKaspersky = document.getElementById('menu-check-kaspersky');
const aboutButton = document.getElementById('about-button');
const aboutModal = document.getElementById('about-modal');
const modalOverlay = document.getElementById('modal-overlay');
const modalCloseButton = document.getElementById('modal-close-button');


// --- CACHES ---
const flaggedEventCache = new Set();
const liveEventCache = new Set();


// --- CONTEXT MENU LOGIC ---
window.addEventListener('click', (e) => {
    contextMenu.style.display = 'none';

    if (e.target === modalOverlay) {
        hideAboutModal();
    }
});

function showContextMenu(e) {
    e.preventDefault(); 
    const eventElement = e.target.closest('li');
    if (!eventElement || !eventElement.dataset.ip) return;

    const ip = eventElement.dataset.ip;
    contextMenu.dataset.ip = ip; 
    
    contextMenu.style.left = `${e.pageX}px`;
    contextMenu.style.top = `${e.pageY}px`;
    contextMenu.style.display = 'block';
}

menuFlagIp.addEventListener('click', (e) => {
    e.stopPropagation(); 
    handleFlagClick();
    contextMenu.style.display = 'none';
});

menuCheckKaspersky.addEventListener('click', (e) => {
    e.stopPropagation();
    const ip = contextMenu.dataset.ip;
    if (ip) {
        window.open(`https://opentip.kaspersky.com/${ip}`, '_blank');
    }
    contextMenu.style.display = 'none';
});


async function handleFlagClick() {
    const ip = contextMenu.dataset.ip;
    if (!ip) return;

    try {
        const response = await fetch(`/api/flag-ip/${ip}`, { method: 'PUT' });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Failed to flag');
        }
        
        alert(`IP ${ip} has been flagged. It will now appear in the 'Flagged Events' log.`);
        
        fetchLiveEvents();
        fetchFlaggedEvents();
        
    } catch (error) {
        console.error(`Error flagging IP ${ip}:`, error);
        alert(`Failed to flag IP: ${error.message}`);
    }
}


// --- DATA FETCHING & RENDERING ---

function createLogElement(event) {
    const eventElement = document.createElement('li');
    eventElement.dataset.ip = event.src_ip; 
    
    const location = event.city || event.country || 'Unknown Location';
    const locationClass = event.city || event.country ? 'log-location' : 'log-location-unknown';
    
    const hostname = event.hostname || 'N/A';
    const isp = event.isp || 'N/A';

    const suspiciousHtml = event.is_suspicious 
        ? `<br>&nbsp;&nbsp;-> <span class="log-suspicious">Flagged as Suspicious</span>` 
        : '';

    eventElement.innerHTML = `
        <span class="log-time">[${new Date(event.timestamp).toLocaleString()}]</span>
        <strong class="log-ip">${event.src_ip}</strong>
        <br>
        &nbsp;&nbsp;-> (Port <span class="log-port">${event.dst_port}</span>)
        | <span class="${locationClass}">${location}</span>
        ${suspiciousHtml}
        <br>
        &nbsp;&nbsp;-> Host: <span class="log-detail">${hostname}</span>
        <br>
        &nbsp;&nbsp;-> <span class="log-detail-isp">ISP:</span> <span class="log-detail">${isp}</span>
    `;
    
    // Add left-click listener to open ipinfo.io
    eventElement.addEventListener('click', () => {
         window.open(`https://ipinfo.io/${event.src_ip}`, '_blank');
    });

    // Add right-click listener to open our custom menu
    if (!event.is_suspicious) { 
        eventElement.addEventListener('contextmenu', showContextMenu);
    }

    return eventElement;
}

async function fetchDrilldownEvents(city, country) {
    let queryString = '';
    let title = 'Unknown Location';
    if (city) {
        queryString = `?city=${encodeURIComponent(city)}`;
        title = city;
    } else if (country) {
        queryString = `?country=${encodeURIComponent(country)}`;
        title = country;
    }

    drilldownTitle.textContent = `Drill Down: ${title}`;
    drilldownLogFeed.innerHTML = '<li>Loading events...</li>';

    try {
        const response = await fetch(`/api/events-by-location${queryString}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const events = await response.json();
        drilldownLogFeed.innerHTML = ''; 

        if (events.length === 0) {
            drilldownLogFeed.innerHTML = '<li>No events found for this location.</li>';
            return;
        }

        events.forEach(event => {
            const eventElement = createLogElement(event);
            drilldownLogFeed.appendChild(eventElement);
        });

    } catch (error) {
        drilldownLogFeed.innerHTML = '<li>Error loading events.</li>';
        console.error('Error fetching drilldown events:', error);
    }
}

async function fetchLiveEvents() {
    try {
        const response = await fetch('/api/recent-events');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const events = await response.json();

        if (liveEventCache.size === 0 && events.length > 0) {
            liveLogFeed.innerHTML = ''; 
        } else if (events.length === 0 && liveEventCache.size === 0) {
             liveLogFeed.innerHTML = '<li>No recent events found.</li>';
        }

        events.forEach(event => {
            const eventKey = `${event.timestamp}-${event.src_ip}-${event.dst_port}`;
            if (!liveEventCache.has(eventKey)) {
                const eventElement = createLogElement(event);
                liveLogFeed.prepend(eventElement); 
                liveEventCache.add(eventKey);
            }
        });
    } catch (error) {
        liveLogFeed.innerHTML = '<li>Error loading events.</li>';
        console.error('Error fetching live events:', error);
    }
}

async function fetchFlaggedEvents() {
    try {
        const response = await fetch('/api/flagged-events');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const events = await response.json();

        if (flaggedEventCache.size === 0 && events.length > 0) {
            flaggedLogFeed.innerHTML = '';
        } else if (events.length === 0 && flaggedEventCache.size === 0) {
            flaggedLogFeed.innerHTML = '<li>No flagged events found yet.</li>';
        }
        
        events.forEach(event => {
            const eventKey = `${event.timestamp}-${event.src_ip}-${event.dst_port}`;
            if (!flaggedEventCache.has(eventKey)) {
                const eventElement = createLogElement(event);
                flaggedLogFeed.prepend(eventElement);
                flaggedEventCache.add(eventKey);
            }
        });
    } catch (error) {
        flaggedLogFeed.innerHTML = '<li>Error loading events.</li>';
        console.error('Error fetching flagged events:', error);
    }
}


async function updateMap() {
    try {
        const response = await fetch('/api/map-data');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const mapData = await response.json();

        markers.clearLayers(); 

        mapData.forEach(location => {
            const marker = L.marker([location.latitude, location.longitude]);

            const tooltipContent = `
                <strong>${location.city || location.country || 'Unknown Location'}</strong><br>
                Total Attempts: ${location.attempt_count}
            `;
            
            marker.bindTooltip(tooltipContent);
            
            marker.on('click', () => {
                fetchDrilldownEvents(location.city, location.country);
            });

            markers.addLayer(marker);
        });

    } catch (error) {
        console.error('Error fetching map data:', error);
    }
}

function trapScroll(el) {
    if (!el) return;
    el.addEventListener('wheel', (e) => {
        const isScrollingUp = e.deltaY < 0;
        const isScrollingDown = e.deltaY > 0;
        
        if (isScrollingUp && el.scrollTop === 0) {
            e.preventDefault();
            return;
        }
        
        const maxScrollTop = el.scrollHeight - el.clientHeight;
        
        if (isScrollingDown && el.scrollTop >= maxScrollTop - 1) {
            e.preventDefault();
            return;
        }
        e.stopPropagation();
    });
}

// --- About Modal Logic ---
function showAboutModal() {
    modalOverlay.classList.add('modal-visible');
    aboutModal.classList.add('modal-visible');
}

function hideAboutModal() {
    modalOverlay.classList.remove('modal-visible');
    aboutModal.classList.remove('modal-visible');
}

aboutButton.addEventListener('click', showAboutModal);
modalCloseButton.addEventListener('click', hideAboutModal);


// --- MAIN EXECUTION ---
updateMap();
fetchLiveEvents();
fetchFlaggedEvents();

trapScroll(drilldownLogFeed);
trapScroll(flaggedLogFeed);
trapScroll(liveLogFeed);

setInterval(updateMap, 30000);
setInterval(fetchLiveEvents, 10000);
setInterval(fetchFlaggedEvents, 10000);
