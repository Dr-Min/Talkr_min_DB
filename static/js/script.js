document.addEventListener("DOMContentLoaded", function () {
  const chatContainer = document.getElementById("chat-container");
  const userInput = document.getElementById("user-input");
  const sendBtn = document.getElementById("send-btn");
  const voiceBtn = document.getElementById("voice-btn");
  const autoMicToggle = document.getElementById("auto-mic-toggle");
  const authModal = document.getElementById("auth-modal");
  const loginBtn = document.getElementById("login-btn");
  const signupBtn = document.getElementById("signup-btn");
  const authMessage = document.getElementById("auth-message");
  const modalTitle = document.getElementById("modal-title");
  const loginForm = document.getElementById("login-form");
  const signupForm = document.getElementById("signup-form");
  const showSignupLink = document.getElementById("show-signup");
  const showLoginLink = document.getElementById("show-login");
  const menuIcon = document.getElementById("menu-icon");
  const sidebar = document.getElementById("sidebar");
  const closeSidebar = document.getElementById("close-sidebar");
  const userId = document.getElementById("user-id");
  const showHistory = document.getElementById("show-history");
  const historyModal = document.getElementById("history-modal");
  const closeHistory = historyModal.querySelector(".close");
  const historyContainer = document.getElementById("history-container");
  const loadingHistory = document.getElementById("loading-history");
  const showForgotPasswordLink = document.getElementById(
    "show-forgot-password"
  );
  const forgotPasswordForm = document.getElementById("forgot-password-form");
  const backToLoginLink = document.getElementById("back-to-login");
  const resetPasswordBtn = document.getElementById("reset-password-btn");

  const showReports = document.getElementById("show-reports");
  const reportsModal = document.getElementById("reports-modal");
  const closeReports = reportsModal.querySelector(".close");
  const reportsContainer = document.getElementById("reports-container");

  const showVocabulary = document.getElementById("show-vocabulary");
  const vocabularyModal = document.getElementById("vocabulary-modal");
  const closeVocabulary = vocabularyModal.querySelector(".close");
  const vocabularyContainer = document.getElementById("vocabulary-container");

  let messageCount = 0;

  let recognition;
  let isMicrophoneActive = false;
  let isAITalking = false;
  let isLoading = false;
  let isListening = false;
  let isProcessing = false;
  let isAutoMicOn = false;
  let currentAudio = null;
  let silenceTimer;
  let hasSpeechStarted = false;
  let sessionStartTime;
  let isLoggedIn = false;
  const silenceThreshold = 1500;
  let lastProcessedResult = "";
  let isTranslating = false;
  let currentDate = null;
  let isLoadingHistory = false;
  let messageQueue = [];
  let pendingMessage = null;

  const REPORT_INTERVAL = 2; // 이 값을 변경하여 보고서 생성 간격을 조정할 수 있습니다.

  function sendMessage(message, isVoiceInput = false) {
    if (message && message.trim() !== "") {
      if (isProcessing) {
        pendingMessage = message;
        showPendingMessageNotification();
      } else {
        messageQueue.push(message);
        processMessageQueue();
        messageCount++;
        if (messageCount % REPORT_INTERVAL === 0) {
          generateReport();
        }
      }
      userInput.value = "";
      if (isVoiceInput) {
        lastProcessedResult = "";
      }
    }
  }

  function setupSpeechRecognition() {
    if ("webkitSpeechRecognition" in window) {
      recognition = new webkitSpeechRecognition();
    } else if ("SpeechRecognition" in window) {
      recognition = new SpeechRecognition();
    } else {
      console.error("음성 인식이 지원되지 않는 브라우저입니다.");
      return;
    }

    recognition.lang = "ko-KR";
    recognition.interimResults = true;
    recognition.continuous = true;

    recognition.onstart = function () {
      console.log("음성 인식이 시작되었습니다.");
      isListening = true;
      voiceBtn.classList.add("active");
      voiceBtn.classList.add("voice-active");
    };

    recognition.onspeechstart = function () {
      console.log("음성이 감지되었습니다.");
      hasSpeechStarted = true;
      clearTimeout(silenceTimer);
    };

    recognition.onresult = function (event) {
      clearTimeout(silenceTimer);

      let currentTranscript = "";

      for (let i = event.resultIndex; i < event.results.length; ++i) {
        if (event.results[i].isFinal) {
          currentTranscript += event.results[i][0].transcript + " ";
        }
      }

      userInput.value = currentTranscript.trim();

      if (currentTranscript.trim() !== lastProcessedResult.trim()) {
        if (currentTranscript.trim() !== "") {
          lastProcessedResult = currentTranscript.trim();
          sendMessage(lastProcessedResult, true);
        }
      }

      startSilenceTimer();
    };

    recognition.onspeechend = function () {
      console.log("음성 입력이 중지되었습니다.");
      startSilenceTimer();
    };

    recognition.onend = function () {
      console.log("음성 인식이 종료되었습니다.");
      isListening = false;
      hasSpeechStarted = false;
      voiceBtn.classList.remove("active");
      voiceBtn.classList.remove("voice-active");

      if (
        userInput.value.trim() !== "" &&
        userInput.value.trim() !== lastProcessedResult
      ) {
        lastProcessedResult = userInput.value.trim();
        sendMessage(lastProcessedResult);
      }

      if (isAutoMicOn && !isAITalking && !isLoading) {
        startListening();
      }
    };

    recognition.onerror = function (event) {
      console.error("음성 인식 오류", event.error);
      stopListening();
      if (isAutoMicOn) {
        setTimeout(startListening, 1000);
      }
    };
  }

  function startSilenceTimer() {
    clearTimeout(silenceTimer);
    silenceTimer = setTimeout(() => {
      if (isListening) {
        console.log("침묵이 감지되어 음성 인식을 중지합니다.");
        stopListening();
      }
    }, silenceThreshold);
  }

  function startListening() {
    if (!recognition) {
      setupSpeechRecognition();
    }

    recognition.start();
    isMicrophoneActive = true;
    voiceBtn.classList.add("active");
    console.log("음성 인식이 시작되었습니다.");
  }

  function stopListening() {
    if (recognition) {
      recognition.stop();
      isMicrophoneActive = false;
      voiceBtn.classList.remove("active");
      console.log("음성 인식이 중지되었습니다.");
    }
  }

  function addLoadingAnimation() {
    isLoading = true;
    if (isAutoMicOn) {
      stopListening();
    }
    const messageDiv = document.createElement("div");
    messageDiv.className = "message bot-message";

    const loadingDiv = document.createElement("div");
    loadingDiv.className = "message-bubble loading";
    loadingDiv.innerHTML = `
          <div class="loading-dots">
              <span></span>
              <span></span>
              <span></span>
          </div>
      `;
    messageDiv.appendChild(loadingDiv);
    chatContainer.appendChild(messageDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    return messageDiv;
  }

  function removeLoadingAnimation(loadingDiv) {
    chatContainer.removeChild(loadingDiv);
    isLoading = false;
    if (isAutoMicOn && !isAITalking) {
      startListening();
    }
  }

  function addMessage(message, isUser, audioData) {
    const messageDiv = document.createElement("div");
    messageDiv.className = `message ${isUser ? "user-message" : "bot-message"}`;

    const messageBubble = document.createElement("div");
    messageBubble.className = "message-bubble";
    messageBubble.textContent = message;
    messageDiv.appendChild(messageBubble);

    if (!isUser) {
      const translateBtn = document.createElement("button");
      translateBtn.className = "translate-btn";
      translateBtn.textContent = "Translate";
      translateBtn.onclick = function () {
        if (!isTranslating) {
          this.classList.toggle("active");
          translateMessage(message, messageDiv, this);
        } else {
          console.log("번역이 이미 진행 중입니다.");
        }
      };
      messageDiv.appendChild(translateBtn);
    }

    chatContainer.appendChild(messageDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;

    if (!isUser && audioData) {
      playAudio(audioData);
    }
  }

  function showPendingMessageNotification() {
    // 알림 UI를 표시하는 로직 (예: 작은 팝업 또는 버튼)
    const notification = document.createElement("div");
    notification.id = "pending-message-notification";
    notification.textContent = "대기 중인 메시지가 있습니다";
    notification.style.display = "none";
    document.body.appendChild(notification);
  }

  function showPendingMessageConfirmation() {
    if (pendingMessage) {
      if (confirm(`Do you want to send this message? "${pendingMessage}"`)) {
        sendMessage(pendingMessage);
      }
      pendingMessage = null;
      document.getElementById("pending-message-notification").style.display =
        "none";
    }
  }

  function processMessageQueue() {
    if (isProcessing || messageQueue.length === 0) {
      return;
    }

    isProcessing = true;
    const message = messageQueue.shift();
    addMessage(message, true);

    const loadingDiv = addLoadingAnimation();
    isLoading = true;
    isAITalking = true;
    stopListening();

    fetch("/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: message }),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then((data) => {
        removeLoadingAnimation(loadingDiv);
        isLoading = false;
        if (data.success) {
          addMessage(data.message, false, data.audio);
        } else {
          throw new Error("서버에서 오류 응답을 받았습니다.");
        }
      })
      .catch((error) => {
        removeLoadingAnimation(loadingDiv);
        isLoading = false;
        isAITalking = false;
        console.error("Error:", error);
        addMessage("네트워크 오류가 발생했습니다. 다시 시도해 주세요.", false);
        if (isAutoMicOn) {
          startListening();
        }
      })
      .finally(() => {
        isProcessing = false;
        if (pendingMessage) {
          showPendingMessageConfirmation();
        } else {
          processMessageQueue();
        }
      });
  }

  function playAudio(audioData) {
    isAITalking = true;
    if (isListening) {
      stopListening();
    }
    currentAudio = new Audio("data:audio/mp3;base64," + audioData);
    currentAudio.play().catch((error) => {
      console.error("오디오 재생 오류:", error);
      isAITalking = false;
      if (isAutoMicOn) {
        startListening();
      }
    });
    currentAudio.onended = function () {
      currentAudio = null;
      isAITalking = false;
      if (isAutoMicOn) {
        startListening();
      }
    };
  }

  function stopAITalking() {
    if (currentAudio) {
      currentAudio.pause();
      currentAudio = null;
    }
    isAITalking = false;
    isLoading = false;
    console.log("AI 발화가 중지되었습니다.");
    if (pendingMessage) {
      showPendingMessageConfirmation();
    }
  }

  voiceBtn.addEventListener("click", function () {
    if (isAITalking || isLoading) {
      stopAITalking();
      return;
    }
    if (isListening) {
      stopListening();
    } else {
      startListening();
    }
  });

  function login() {
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;

    fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username: username, password: password }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          isLoggedIn = true;
          authModal.style.display = "none";
          updateUserId(username);
          sessionStartTime = new Date();
          startUsageTracking();
        } else {
          setMessage("Failed to log in. Please try again.", "error");
        }
      })
      .catch((error) => {
        console.error("Login error:", error);
        setMessage(
          "An error occurred while logging in. Please try again.",
          "error"
        );
      });
  }

  function isValidEmail(email) {
    const re =
      /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
  }

  function signup() {
    const username = document.getElementById("signup-username").value.trim();
    const email = document.getElementById("signup-email").value.trim();
    const password = document.getElementById("signup-password").value;

    if (!username || !email || !password) {
      setMessage("Please fill in all fields.", "success");
      return;
    }

    if (!email) {
      setMessage(
        "Buddy, don't tell me you don't have an email? It's the 21st century.",
        "success"
      );
      return;
    }

    if (!isValidEmail(email)) {
      setMessage(
        "The email format is wrong. Hey friend, don't you know email formats in the 21st century?",
        "success"
      );
      return;
    }

    if (password.length < 4) {
      sendMessage(
        `What? Seriously? A ${password.length}-character password? Please make it longer. (At least 4 characters)`,
        "error"
      );
      return;
    }

    fetch("/signup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        email: email,
        password: password,
      }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          setMessage("Sign up successful. Please log in.", "success");
          showLoginLink.click();
        } else if (data.error === "username_taken") {
          setMessage(
            `Okay, ${username} is good name, but someone's already using it. Life is first come, first served.`,
            "success"
          );
        } else {
          setMessage(
            "The email is duplicated. Do you already have an account?",
            "error"
          );
        }
      })
      .catch((error) => {
        console.error("Signup error:", error);
        sendMessage(
          "An error occurred during sign up. Please try again.",
          "error"
        );
      });
  }

  function startUsageTracking() {
    setInterval(() => {
      const currentTime = new Date();
      const usageTime = Math.floor((currentTime - sessionStartTime) / 1000);
      updateUsageTime(usageTime);
    }, 60000);
  }

  function updateUsageTime(time) {
    fetch("/update_usage_time", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ time: time }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (!data.success) {
          console.error("사용 시간 업데이트 실패");
        }
      })
      .catch((error) => {
        console.error("Usage time update error:", error);
      });
  }

  function stopAITalking() {
    if (currentAudio) {
      currentAudio.pause();
      currentAudio = null;
    }
    isAITalking = false;
    isLoading = false;
    console.log("AI 발화가 중지되었습니다.");
  }

  function translateMessage(message, messageDiv, translateBtn) {
    if (isTranslating) {
      console.log("번역이 이미 진행 중입니다.");
      return;
    }

    const existingTranslation = messageDiv.querySelector(".translation");
    if (existingTranslation) {
      existingTranslation.style.display =
        existingTranslation.style.display === "none" ? "block" : "none";
      return;
    }

    isTranslating = true;
    translateBtn.disabled = true;

    const loadingDiv = addTranslationLoadingAnimation(messageDiv);

    fetch("/translate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text: message }),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then((data) => {
        if (data.translation) {
          const translationDiv = document.createElement("div");
          translationDiv.className = "translation";
          translationDiv.textContent = data.translation;
          messageDiv.appendChild(translationDiv);
          translationDiv.style.display = "block";
          chatContainer.scrollTop = chatContainer.scrollHeight;
        } else {
          throw new Error("번역 데이터가 없습니다.");
        }
      })
      .catch((error) => {
        console.error("Translation error:", error);
        addMessage("번역 중 오류가 발생했습니다. 다시 시도해 주세요.", false);
        translateBtn.classList.remove("active");
      })
      .finally(() => {
        removeTranslationLoadingAnimation(loadingDiv);
        isTranslating = false;
        translateBtn.disabled = false;
      });
  }

  function addTranslationLoadingAnimation(container) {
    const loadingDiv = document.createElement("div");
    loadingDiv.className = "loading-animation";
    loadingDiv.innerHTML = '<div class="boxLoading"></div>';
    container.appendChild(loadingDiv);
    return loadingDiv;
  }

  function removeTranslationLoadingAnimation(loadingDiv) {
    if (loadingDiv && loadingDiv.parentNode) {
      loadingDiv.parentNode.removeChild(loadingDiv);
    }
  }

  function updateUserId(username) {
    userId.textContent = username;
  }

  function displayHistory(history) {
    console.log("Displaying history", history);
    if (!historyContainer) {
      console.error("History container not found");
      return;
    }
    historyContainer.innerHTML = "";
    let currentDate = null;
    history.forEach((item) => {
      if (item.date !== currentDate) {
        currentDate = item.date;
        const dateElement = document.createElement("div");
        dateElement.className = "history-date";
        dateElement.textContent = currentDate;
        historyContainer.appendChild(dateElement);
      }
      item.messages.forEach((msg) => {
        const messageDiv = document.createElement("div");
        messageDiv.className = `message ${
          msg.is_user ? "user-message" : "bot-message"
        }`;
        messageDiv.innerHTML = `
                <div class="message-bubble">
                    ${msg.content}
                </div>
                <div class="message-time">${msg.timestamp}</div>
            `;
        historyContainer.appendChild(messageDiv);
      });
    });
  }

  function loadHistory(date = null) {
    if (isLoadingHistory) return;
    isLoadingHistory = true;
    loadingHistory.style.display = "block";

    fetch(`/get_history?date=${date || ""}`)
      .then((response) => response.json())
      .then((data) => {
        displayHistory(data.history);
        isLoadingHistory = false;
        loadingHistory.style.display = "none";
      })
      .catch((error) => {
        console.error("Error loading history:", error);
        isLoadingHistory = false;
        loadingHistory.style.display = "none";
      });
  }

  function addHistoryMessage(msg) {
    const messageDiv = document.createElement("div");
    messageDiv.className = `message ${
      msg.is_user ? "user-message" : "bot-message"
    }`;
    messageDiv.innerHTML = `
      <div class="message-bubble">
        ${msg.content}
      </div>
      <div class="message-time">${msg.timestamp}</div>
    `;
    historyContainer.appendChild(messageDiv);
  }

  sendBtn.addEventListener("click", () => {
    const message = userInput.value.trim();
    if (message !== "") {
      sendMessage(message);
    }
  });

  userInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      const message = userInput.value.trim();
      if (message !== "") {
        sendMessage(message);
      }
    }
  });

  function clearAuthMessage() {
    const authMessage = document.getElementById("auth-message");
    if (authMessage) {
      authMessage.textContent = "";
      authMessage.className = ""; // 클래스도 제거합니다 (에러/성공 스타일 초기화)
    }
  }

  showSignupLink.addEventListener("click", function (e) {
    e.preventDefault();
    clearAuthMessage();
    modalTitle.textContent = "Sign Up";
    loginForm.style.display = "none";
    signupForm.style.display = "block";
  });

  showLoginLink.addEventListener("click", function (e) {
    e.preventDefault();
    clearAuthMessage();
    modalTitle.textContent = "Login";
    signupForm.style.display = "none";
    loginForm.style.display = "block";
  });

  voiceBtn.addEventListener("click", function () {
    if (isAITalking || isLoading) {
      stopAITalking();
      return;
    }
    if (isListening) {
      stopListening();
    } else {
      startListening();
    }
  });

  autoMicToggle.addEventListener("click", function () {
    isAutoMicOn = !isAutoMicOn;
    autoMicToggle.textContent = isAutoMicOn ? "Auto Mic: ON" : "Auto Mic: OFF";
    autoMicToggle.classList.toggle("active");
    if (isAutoMicOn && !isAITalking && !isLoading) {
      startListening();
    } else if (!isAutoMicOn) {
      stopListening();
    }
  });

  loginBtn.addEventListener("click", login);
  signupBtn.addEventListener("click", signup);

  menuIcon.addEventListener("click", function () {
    sidebar.style.width = "50%";
  });

  closeSidebar.addEventListener("click", function () {
    sidebar.style.width = "0";
  });

  showHistory.addEventListener("click", function () {
    historyModal.style.display = "block";
    historyContainer.innerHTML = "<p>Loading history...</p>";
    currentDate = null;
    loadHistory();
    console.log("History modal opened"); // 디버깅용 로그
  });

  closeHistory.addEventListener("click", function () {
    historyModal.style.display = "none";
  });

  historyContainer.addEventListener("scroll", () => {
    if (historyContainer.scrollTop === 0 && !isLoadingHistory) {
      loadHistory(currentDate);
    }
  });

  // 비밀번호 찾기 관련 이벤트 리스너
  showForgotPasswordLink.addEventListener("click", function (e) {
    e.preventDefault();
    clearAuthMessage();
    loginForm.style.display = "none";
    signupForm.style.display = "none";
    forgotPasswordForm.style.display = "block";
    modalTitle.textContent = "Reset Password";
  });

  backToLoginLink.addEventListener("click", function (e) {
    e.preventDefault();
    clearAuthMessage();
    forgotPasswordForm.style.display = "none";
    loginForm.style.display = "block";
    modalTitle.textContent = "Login";
  });

  resetPasswordBtn.addEventListener("click", function () {
    const email = document.getElementById("reset-email").value;
    const loadingAnimation = document.getElementById("loading-animation");
    const authMessage = document.getElementById("auth-message");

    if (!isValidEmail(email)) {
      setMessage("Please enter a valid email address.", "error");
      return;
    }

    loadingAnimation.style.display = "block";
    resetPasswordBtn.disabled = true;
    clearMessage();

    fetch("/request_reset", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email: email }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.message === "Reset link sent to your email") {
          setMessage(data.message, "success");
        } else {
          setMessage(data.message, "error");
        }
      })
      .catch((error) => {
        console.error("Error:", error);
        setMessage("An error occurred. Please try again.", "error");
      })
      .finally(() => {
        loadingAnimation.style.display = "none";
        resetPasswordBtn.disabled = false;
      });
  });

  function setMessage(message, type) {
    const authMessage = document.getElementById("auth-message");
    authMessage.textContent = message;
    authMessage.className = type ? type + "-message" : "";
  }

  function clearMessage() {
    const authMessage = document.getElementById("auth-message");
    authMessage.textContent = "";
    authMessage.className = "";
  }
  function checkLoginStatus() {
    fetch("/check_login")
      .then((response) => response.json())
      .then((data) => {
        if (data.logged_in) {
          isLoggedIn = true;
          updateUserId(data.username);
          authModal.style.display = "none";
        } else {
          showLoginForm();
        }
      })
      .catch((error) => {
        console.error("Error:", error);
        showLoginForm();
      });
  }

  function showLoginForm() {
    authModal.style.display = "block";
    modalTitle.textContent = "Login";
    loginForm.style.display = "block";
    signupForm.style.display = "none";
  }

  // 페이지 로드 시 로그인 상태 확인
  checkLoginStatus();

  // 로그아웃 함수 수정
  function logout() {
    fetch("/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          isLoggedIn = false;
          showLoginForm();
          sidebar.style.width = "0"; // 사이드바 닫기
        }
      })
      .catch((error) => console.error("Logout error:", error));
  }
  // 로그아웃 버튼에 이벤트 리스너 추가
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", logout);
  }

  function checkMessageCount() {
    messageCount++;
    if (messageCount % 2 === 0) {
      generateReport();
    }
  }

  function generateReport() {
    fetch("/generate_report", {
      method: "POST",
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          alert("New report generated!");
          loadReports();
        }
      })
      .catch((error) => console.error("Error generating report:", error));
  }

  showReports.addEventListener("click", function () {
    reportsModal.style.display = "block";
    loadReports();
  });

  closeReports.addEventListener("click", function () {
    reportsModal.style.display = "none";
  });

  function loadReports() {
    fetch("/get_reports")
      .then((response) => response.json())
      .then((reports) => {
        reportsContainer.innerHTML = "";
        reports.forEach((report) => {
          const reportButton = document.createElement("button");
          reportButton.textContent = `Report ${report.report_number}`;
          reportButton.onclick = () => showReportContent(report);
          reportsContainer.appendChild(reportButton);
        });
      })
      .catch((error) => console.error("Error loading reports:", error));
  }

  function showReportContent(report) {
    const contentDiv = document.createElement("div");
    contentDiv.innerHTML = `
      <h3>Report ${report.report_number}</h3>
      <p>Created: ${report.timestamp}</p>
      <pre>${report.content}</pre>
    `;

    const closeButton = document.createElement("button");
    closeButton.textContent = "Close";
    closeButton.onclick = () => loadReports();

    const deleteButton = document.createElement("button");
    deleteButton.textContent = "Delete Report";
    deleteButton.onclick = () => deleteReport(report.id);

    reportsContainer.innerHTML = "";
    reportsContainer.appendChild(contentDiv);
    reportsContainer.appendChild(closeButton);
    reportsContainer.appendChild(deleteButton);
  }

  function deleteReport(reportId) {
    if (confirm("Are you sure you want to delete this report?")) {
      fetch(`/delete_report/${reportId}`, { method: "DELETE" })
        .then((response) => response.json())
        .then((data) => {
          if (data.success) {
            loadReports();
          } else {
            alert("Failed to delete report");
          }
        })
        .catch((error) => console.error("Error deleting report:", error));
    }
  }

  showVocabulary.addEventListener("click", function () {
    vocabularyModal.style.display = "block";
    loadVocabulary();
  });

  closeVocabulary.addEventListener("click", function () {
    vocabularyModal.style.display = "none";
  });

  function loadVocabulary() {
    fetch("/get_vocabulary")
      .then((response) => response.json())
      .then((vocabulary) => {
        vocabularyContainer.innerHTML = "";
        vocabulary.forEach((item) => {
          const wordElement = document.createElement("div");
          wordElement.innerHTML = `
            <strong>${item.word}</strong>: ${item.count}
          `;
          vocabularyContainer.appendChild(wordElement);
        });
      })
      .catch((error) => console.error("Error loading vocabulary:", error));
  }

  setupSpeechRecognition();
  modalTitle.textContent = "Login";
  loginForm.style.display = "block";
  signupForm.style.display = "none";
  authModal.style.display = "block";
});
