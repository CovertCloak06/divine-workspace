/**
 * History Module
 * Manages chat history rendering, navigation, and operations
 */

import { loadChatsFromStorage, saveChatsToStorage, loadProjectsFromStorage, saveProjectsToStorage } from '../utils/storage.js';
import { closeHistoryMenu } from '../utils/utils.js';
import { addMessage } from '../ui/chat.js';

// DOM references (initialized in initHistory)
let historyList = null;
let favoritesList = null;
let archiveList = null;
let messagesContainer = null;
let fullHistoryToggle = null;

/**
 * Clear messages from container while preserving welcome screen
 */
function clearMessages() {
    if (!messagesContainer) return;
    // Remove only .message elements, preserve welcome screen
    messagesContainer.querySelectorAll('.message').forEach(el => el.remove());
}

/**
 * Initialize history module with DOM references
 */
export function initHistory() {
    historyList = document.getElementById('historyList');
    favoritesList = document.getElementById('favoritesList');
    archiveList = document.getElementById('archiveList');
    messagesContainer = document.getElementById('messagesContainer');
    fullHistoryToggle = document.getElementById('fullHistoryToggle');
}

/**
 * Sort chats by updated time (newest first)
 */
export function sortChats(chats) {
    return chats.sort((a, b) => {
        const aTime = a.updatedAt || 0;
        const bTime = b.updatedAt || 0;
        return bTime - aTime;
    });
}

/**
 * Render chat history in sidebar
 */
export function renderHistory() {
    if (!historyList) initHistory();
    if (!historyList) return;

    historyList.innerHTML = '';
    favoritesList.innerHTML = '';
    archiveList.innerHTML = '';

    let chats = loadChatsFromStorage();
    chats = sortChats(chats);

    // Add "+ New chat" button at top
    const newChatBtn = document.createElement('div');
    newChatBtn.className = 'history-item new-chat-btn';
    newChatBtn.innerHTML = '<span class="history-title">+ New chat</span>';
    newChatBtn.onclick = () => newChat();
    historyList.appendChild(newChatBtn);

    chats.forEach(chat => {
        const item = document.createElement('div');
        item.className = 'history-item' + (chat.id === window.currentChatId ? ' active' : '');
        item.dataset.chatId = chat.id;

        const title = document.createElement('span');
        title.className = 'history-title';
        title.textContent = chat.title || 'Untitled chat';
        title.onclick = (e) => {
            e.stopPropagation();
            loadChat(chat.id);
        };
        item.appendChild(title);

        const menuBtn = document.createElement('button');
        menuBtn.className = 'history-menu-btn';
        menuBtn.textContent = '\u22EE';
        menuBtn.onclick = (e) => {
            e.stopPropagation();
            openHistoryMenu(chat.id, menuBtn, !!chat.starred, !!chat.archived);
        };
        item.appendChild(menuBtn);

        if (chat.archived) {
            archiveList.appendChild(item);
        } else if (chat.starred) {
            favoritesList.appendChild(item);
        } else {
            historyList.appendChild(item);
        }
    });

    // Empty state messages
    addEmptyState(favoritesList, '\u2B50', 'No favorites yet', 'Star chats to see them here');
    addEmptyState(archiveList, '\uD83D\uDCE6', 'No archived chats', 'Archive old chats to keep them organized');
    if (historyList.children.length === 1) {
        addEmptyState(historyList, '\uD83D\uDCAC', 'No chats yet', 'Start a new conversation');
    }
}

function addEmptyState(container, icon, text, hint) {
    if (container.children.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state';
        emptyState.innerHTML = `
            <div class="empty-state-icon">${icon}</div>
            <div class="empty-state-text">${text}</div>
            <div class="empty-state-hint">${hint}</div>
        `;
        container.appendChild(emptyState);
    }
}

/**
 * Open context menu for a chat item
 */
export function openHistoryMenu(chatId, anchorButton, isStarred, isArchived) {
    closeHistoryMenu();

    const rect = anchorButton.getBoundingClientRect();
    const containerRect = document.body.getBoundingClientRect();

    const menu = document.createElement('div');
    menu.className = 'history-menu';

    const menuItems = [
        { text: isStarred ? 'Unfavorite' : 'Add to favorites', action: () => toggleFavoriteChat(chatId) },
        { text: isArchived ? 'Unarchive' : 'Archive chat', action: () => toggleArchiveChat(chatId) },
        { text: 'Rename chat', action: () => renameChatPrompt(chatId) },
        { text: 'Move to Project', action: () => window.showMoveToProjectModal?.(chatId) },
        { text: 'Delete chat', action: () => deleteChat(chatId) }
    ];

    menuItems.forEach(({ text, action }) => {
        const item = document.createElement('div');
        item.className = 'history-menu-item';
        item.textContent = text;
        item.onclick = () => { action(); closeHistoryMenu(); };
        menu.appendChild(item);
    });

    menu.style.top = (rect.top - containerRect.top + window.scrollY) + 'px';
    menu.style.left = (rect.left - containerRect.left + window.scrollX) + 'px';

    document.body.appendChild(menu);
    window.openMenuElement = menu;
}

/**
 * Toggle favorite status of a chat
 */
export function toggleFavoriteChat(id) {
    // Global chats
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === id);
    if (chat) {
        chat.starred = !chat.starred;
        chat.updatedAt = Date.now();
        saveChatsToStorage(chats);
        renderHistory();
        return;
    }

    // Project chats
    let projects = loadProjectsFromStorage();
    for (const project of projects) {
        const projChat = project.chats?.find(c => c.id === id);
        if (projChat) {
            projChat.starred = !projChat.starred;
            projChat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            window.renderProjects?.();
            return;
        }
    }
}

/**
 * Toggle archive status of a chat
 */
export function toggleArchiveChat(id) {
    // Global chats
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === id);
    if (chat) {
        chat.archived = !chat.archived;
        chat.updatedAt = Date.now();
        saveChatsToStorage(chats);
        renderHistory();
        return;
    }

    // Project chats
    let projects = loadProjectsFromStorage();
    for (const project of projects) {
        const projChat = project.chats?.find(c => c.id === id);
        if (projChat) {
            projChat.archived = !projChat.archived;
            projChat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            window.renderProjects?.();
            return;
        }
    }
}

/**
 * Load and display a chat by ID
 */
export function loadChat(id) {
    if (!messagesContainer) initHistory();

    // Try global chats first
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === id);
    if (chat) {
        window.currentProjectId = null;
        window.currentChatId = id;
        clearMessages();
        chat.messages.forEach(m => addMessage(m.text, m.sender, false, m.attachments, m.id, m.model, m.timestamp));
        if (fullHistoryToggle) fullHistoryToggle.checked = chat.useFullHistory !== false;
        window.renderProjects?.();
        renderHistory();
        setTimeout(() => window.showWelcomeScreen?.(), 50);
        return;
    }

    // Search project chats
    const projects = loadProjectsFromStorage();
    for (const project of projects) {
        const projChat = (project.chats || []).find(c => c.id === id);
        if (projChat) {
            window.currentProjectId = project.id;
            window.currentChatId = id;
            clearMessages();
            projChat.messages.forEach(m => addMessage(m.text, m.sender, false, m.attachments || [], m.id, m.model, m.timestamp));
            if (fullHistoryToggle) fullHistoryToggle.checked = projChat.useFullHistory !== false;
            window.renderProjects?.();
            renderHistory();
            setTimeout(() => window.showWelcomeScreen?.(), 50);
            return;
        }
    }

    console.warn('Chat not found:', id);
}

/**
 * Reload the current chat from storage
 */
export function reloadCurrentChat() {
    if (!window.currentChatId) return;
    if (!messagesContainer) initHistory();

    clearMessages();

    if (window.currentProjectId) {
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === window.currentProjectId);
        const chat = project?.chats?.find(c => c.id === window.currentChatId);
        chat?.messages?.forEach(m => addMessage(m.text, m.sender, false, m.attachments || [], m.id, m.model, m.timestamp));
    } else {
        const chats = loadChatsFromStorage();
        const chat = chats.find(c => c.id === window.currentChatId);
        chat?.messages?.forEach(m => addMessage(m.text, m.sender, false, m.attachments, m.id, m.model, m.timestamp));
    }

    setTimeout(() => window.showWelcomeScreen?.(), 50);
}

/**
 * Delete a chat by ID
 */
export function deleteChat(id) {
    if (!messagesContainer) initHistory();

    // Try global chats first
    let chats = loadChatsFromStorage();
    if (chats.find(c => c.id === id)) {
        chats = chats.filter(c => c.id !== id);
        saveChatsToStorage(chats);
        if (window.currentChatId === id) {
            window.currentChatId = null;
            clearMessages();
        }
        renderHistory();
        return;
    }

    // Search projects
    let projects = loadProjectsFromStorage();
    for (const project of projects) {
        if (project.chats?.find(c => c.id === id)) {
            project.chats = project.chats.filter(c => c.id !== id);
            saveProjectsToStorage(projects);
            if (window.currentChatId === id) {
                window.currentChatId = null;
                clearMessages();
            }
            window.renderProjects?.();
            return;
        }
    }
}

/**
 * Prompt user to rename a chat
 */
export function renameChatPrompt(chatId) {
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === chatId);

    if (!chat) {
        const projects = loadProjectsFromStorage();
        for (const project of projects) {
            chat = project.chats?.find(c => c.id === chatId);
            if (chat) break;
        }
    }

    if (!chat) return;

    const newTitle = prompt('Enter new chat name:', chat.title);
    if (newTitle !== null && newTitle.trim() !== '') {
        renameChat(chatId, newTitle.trim());
    }
}

/**
 * Rename a chat
 */
export function renameChat(chatId, newTitle) {
    // Try global chats first
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === chatId);
    if (chat) {
        chat.title = newTitle;
        chat.updatedAt = Date.now();
        saveChatsToStorage(chats);
        renderHistory();
        return;
    }

    // Search projects
    const projects = loadProjectsFromStorage();
    for (const project of projects) {
        const projChat = project.chats?.find(c => c.id === chatId);
        if (projChat) {
            projChat.title = newTitle;
            projChat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            window.renderProjects?.();
            return;
        }
    }
}

/**
 * Create a new chat
 */
export function newChat() {
    if (!messagesContainer) initHistory();

    const id = 'chat_' + Date.now();

    // If in project mode, create project-local chat
    if (window.currentProjectId) {
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === window.currentProjectId);
        if (project) {
            project.chats = project.chats || [];
            project.chats.unshift({
                id,
                title: 'Project Chat',
                messages: [],
                starred: false,
                archived: false,
                useFullHistory: true,
                updatedAt: Date.now()
            });
            saveProjectsToStorage(projects);
            window.currentChatId = id;
            clearMessages();
            window.renderProjects?.();
            renderHistory();
            setTimeout(() => window.showWelcomeScreen?.(), 50);
            return;
        }
    }

    // Global chat
    const chats = loadChatsFromStorage();
    chats.unshift({
        id,
        title: 'New chat',
        messages: [],
        starred: false,
        archived: false,
        useFullHistory: true,
        updatedAt: Date.now()
    });
    saveChatsToStorage(chats);
    window.currentChatId = id;
    window.currentProjectId = null;
    clearMessages();
    window.renderProjects?.();
    renderHistory();
    setTimeout(() => window.showWelcomeScreen?.(), 50);
}

/**
 * Export chats to JSON backup file
 */
export function backupChat() {
    const chats = loadChatsFromStorage();
    const blob = new Blob([JSON.stringify(chats, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'parakleon_chat_backup.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Import chats from JSON backup file
 */
export function importBackup() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (ev) => {
            try {
                const imported = JSON.parse(ev.target.result);
                if (!Array.isArray(imported)) {
                    throw new Error('Invalid backup format');
                }
                const existing = loadChatsFromStorage();
                const merged = [...imported, ...existing];
                saveChatsToStorage(merged);
                renderHistory();
                window.showToast?.('Backup imported successfully', 3000, 'success');
            } catch (err) {
                console.error('Import failed:', err);
                window.showToast?.('Failed to import backup: ' + err.message, 5000, 'error');
            }
        };
        reader.readAsText(file);
    };
    input.click();
}

// Setup global click handler for closing menus
if (typeof document !== 'undefined') {
    document.addEventListener('click', (e) => {
        const activeMenu = window.openMenuElement;
        if (activeMenu) {
            const clickedInsideMenu = activeMenu.contains(e.target);
            const clickedMenuButton = e.target.classList.contains('history-menu-btn') ||
                                      e.target.closest('.history-menu-btn');
            if (!clickedInsideMenu && !clickedMenuButton) {
                closeHistoryMenu();
            }
        }
    }, true);
}
