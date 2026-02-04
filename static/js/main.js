document.addEventListener("DOMContentLoaded", () => {
  // --- Global Elements ---
  const modal = document.getElementById("modal");
  const settingsModal = document.getElementById("settingsModal");
  const trashFab = document.querySelector(".fab-trash");
  const searchBar = document.getElementById("searchBar");
  
  // --- Helper Functions ---
  const openModalFn = (m) => m && m.classList.add("open");
  const closeModalFn = (m) => m && m.classList.remove("open");
  
  // --- Main Modal (Add/Edit Task) ---
  const openModalBtn = document.getElementById("openModal");
  const closeModalBtn = document.getElementById("closeModal");
  const taskForm = document.getElementById("taskForm");
  const modalTitle = document.getElementById("modalTitle");
  const taskClientName = document.getElementById("taskClientName");
  const taskNotes = document.getElementById("taskNotes");
  const modalSubmitBtn = document.getElementById("modalSubmitBtn");

  function openTaskModal(isEdit, data = {}) {
      if (!modal) return;
      
      if (isEdit) {
          modalTitle.textContent = "Editar Tarefa";
          taskForm.action = `/tasks/edit/${data.id}`;
          taskClientName.value = data.client;
          taskNotes.value = data.notes;
          
          // Select Color
          const colorInput = taskForm.querySelector(`input[name="color"][value="${data.color}"]`);
          if (colorInput) colorInput.checked = true;
          
          // Select Status
          const statusInput = taskForm.querySelector(`input[name="status"][value="${data.status}"]`);
          if (statusInput) statusInput.checked = true;
          
          modalSubmitBtn.textContent = "Atualizar";
      } else {
          modalTitle.textContent = "Adicionar Tarefa";
          taskForm.action = "/tasks"; 
          taskForm.reset();
          // Reset color to first one
          const firstColor = taskForm.querySelector('input[name="color"]');
          if (firstColor) firstColor.checked = true;
          // Reset status to first one (or default)
          const firstStatus = taskForm.querySelector('input[name="status"][value="em_atendimento"]');
          if (firstStatus) firstStatus.checked = true;
          
          modalSubmitBtn.textContent = "Salvar";
      }
      
      openModalFn(modal);
      
      // Trigger auto-resize for notes
      if (taskNotes) {
        taskNotes.style.height = 'auto';
        taskNotes.style.height = taskNotes.scrollHeight + 'px';
      }
  }

  if (openModalBtn) openModalBtn.addEventListener("click", () => openTaskModal(false));
  if (closeModalBtn) closeModalBtn.addEventListener("click", () => closeModalFn(modal));
  if (modal) {
      modal.addEventListener("click", (e) => {
          if (e.target === modal) closeModalFn(modal);
      });
  }

  // --- Settings Modal ---
  const settingsToggle = document.getElementById("settingsToggle");
  const closeSettings = document.getElementById("closeSettings");

  if (settingsToggle) settingsToggle.addEventListener("click", () => openModalFn(settingsModal));
  if (closeSettings) closeSettings.addEventListener("click", () => closeModalFn(settingsModal));
  if (settingsModal) {
      settingsModal.addEventListener("click", (e) => {
          if (e.target === settingsModal) closeModalFn(settingsModal);
      });
  }

  // --- Search Bar ---
  const searchToggle = document.getElementById("searchToggle");
  if (searchToggle && searchBar) {
      searchToggle.addEventListener("click", () => searchBar.classList.toggle("open"));
  }

  // --- Auto Resize Textareas ---
  const autoTextareas = document.querySelectorAll("textarea.auto-resize");
  autoTextareas.forEach((ta) => {
      const resize = () => {
          ta.style.height = "auto";
          ta.style.height = `${ta.scrollHeight}px`;
      };
      ta.addEventListener("input", resize);
      // Initial resize
      setTimeout(resize, 0); // Delay slightly to ensure visibility
  });

  // --- Menu Dropdowns ---
  document.querySelectorAll(".menu").forEach((menu) => {
      const btn = menu.querySelector(".menu-btn");
      if (!btn) return;
      btn.addEventListener("click", (e) => {
          e.stopPropagation();
          // Close others
          document.querySelectorAll(".menu.open").forEach(m => {
              if (m !== menu) m.classList.remove("open");
          });
          menu.classList.toggle("open");
      });
  });
  
  document.addEventListener("click", () => {
      document.querySelectorAll(".menu.open").forEach((m) => m.classList.remove("open"));
  });

  // --- Flash Messages ---
  const flashes = document.querySelectorAll(".flash");
  if (flashes.length) {
      setTimeout(() => {
          flashes.forEach((f) => f.remove());
      }, 3000);
  }

  // --- Theme Logic ---
  const savedTheme = localStorage.getItem("theme") || "light";
  document.documentElement.setAttribute("data-theme", savedTheme);
  const themeRadios = document.querySelectorAll('input[name="theme"]');
  themeRadios.forEach(r => {
      if (r.value === savedTheme) r.checked = true;
  });
  
  window.setTheme = (theme) => {
      document.documentElement.setAttribute("data-theme", theme);
      localStorage.setItem("theme", theme);
  };
  const saveThemeBtn = document.getElementById("saveThemeBtn");
  if (saveThemeBtn) {
      saveThemeBtn.addEventListener("click", () => {
          const selected = document.querySelector('input[name="theme"]:checked');
          if (selected) {
              setTheme(selected.value);
              closeModalFn(settingsModal);
          }
      });
  }

  // --- Trash Select All ---
  const trashSelectAll = document.getElementById("trashSelectAll");
  if (trashSelectAll) {
      trashSelectAll.addEventListener("click", () => {
          const checkboxes = document.querySelectorAll('input[name="task_ids"]');
          const allChecked = Array.from(checkboxes).every(c => c.checked);
          checkboxes.forEach(c => c.checked = !allChecked);
      });
  }

  // --- Main Board Select All ---
  const selectAllBtn = document.getElementById("selectAllBtn");
  
  if (selectAllBtn) {
      selectAllBtn.addEventListener("click", () => {
          const checkboxes = document.querySelectorAll(".card-select-checkbox");
          if (!checkboxes.length) return;
          
          // Check visibility using offsetParent (null if hidden)
          const isHidden = checkboxes[0].offsetParent === null;
          
          if (isHidden) {
              // Enter Selection Mode
              checkboxes.forEach(c => {
                  c.style.display = "block";
                  c.checked = true;
              });
              if (trashFab) trashFab.style.display = "block";
          } else {
              // Exit Selection Mode completely
              checkboxes.forEach(c => {
                  c.checked = false;
                  c.style.display = "none";
              });
              if (trashFab) trashFab.style.display = "none";
          }
      });
  }

  // --- Edit Buttons Delegation ---
  document.addEventListener("click", (e) => {
      if (e.target.classList.contains("edit-card-btn")) {
          const card = e.target.closest(".card");
          const rawNotes = card.querySelector(".raw-notes");
          
          if (!card.dataset.id) {
              console.error("Card ID missing");
              alert("Erro: Não foi possível identificar o card.");
              return;
          }

          const data = {
              id: card.dataset.id,
              client: card.dataset.client,
              notes: rawNotes ? rawNotes.textContent : "",
              status: card.dataset.status,
              color: card.dataset.color
          };
          openTaskModal(true, data);
          // Close the menu
          const menuList = e.target.closest(".menu-list");
          if(menuList) {
             menuList.closest(".menu").classList.remove("open");
          }
      }
  });

  // --- Monitor manual checkbox clicks to toggle trash fab ---
  document.body.addEventListener("change", (e) => {
      if (e.target.classList.contains("card-select-checkbox")) {
          if (trashFab) {
             const anyChecked = document.querySelectorAll(".card-select-checkbox:checked").length > 0;
             trashFab.style.display = anyChecked ? "block" : "none";
          }
      }
  });
});
