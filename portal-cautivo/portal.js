(function () {
    "use strict";

    function formatTime(totalSeconds) {
        var hours = Math.floor(totalSeconds / 3600);
        var minutes = Math.floor((totalSeconds % 3600) / 60);
        var seconds = totalSeconds % 60;
        var parts = [minutes, seconds];

        if (hours > 0) {
            parts.unshift(hours);
        }

        return parts.map(function (part) {
            return String(part).padStart(2, "0");
        }).join(":");
    }

    function startSessionTimer() {
        var timer = document.getElementById("session-timer");
        var expiredNotice = document.getElementById("expired-notice");
        if (!timer || !timer.dataset.seconds) {
            return;
        }

        var remaining = Number.parseInt(timer.dataset.seconds, 10);
        if (!Number.isFinite(remaining) || remaining <= 0) {
            return;
        }

        function update() {
            timer.textContent = formatTime(remaining);
            if (remaining === 0) {
                document.body.classList.add("session-expired");
                expiredNotice.hidden = false;
                window.clearInterval(intervalId);
                return;
            }
            remaining -= 1;
        }

        var intervalId = window.setInterval(update, 1000);
        update();
    }

    function initializeQuiz() {
        var form = document.getElementById("quiz-form");
        if (!form) {
            return;
        }

        var feedback = ["quiz-empty", "quiz-success", "quiz-error"].map(function (id) {
            return document.getElementById(id);
        });

        form.addEventListener("submit", function (event) {
            event.preventDefault();
            feedback.forEach(function (element) {
                element.hidden = true;
            });

            var selected = form.querySelector("input[name='quiz-answer']:checked");
            if (!selected) {
                document.getElementById("quiz-empty").hidden = false;
                return;
            }

            var resultId = selected.value === form.dataset.answer ? "quiz-success" : "quiz-error";
            document.getElementById(resultId).hidden = false;
        });
    }

    startSessionTimer();
    initializeQuiz();
}());
