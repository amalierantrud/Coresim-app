// Panel som kan lukkes og åpnes med en pil ved overskriften.
//
// Bruk i et dashboard: <dashboard script="lukkbar.js"> og <panel id="lukkbar_NAVN">.
// Innholdet som skal skjules får depends="$vis_NAVN$". Pilen setter og fjerner tokenet vis_NAVN.
// Panelet er lukket når siden åpnes, med mindre brukeren hadde det åpent sist (huskes i nettleseren).
// Etter endringer her: åpne http://localhost:8000/en-US/_bump så Splunk ikke bruker en gammel versjon.
require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function ($, mvc) {
    var tokens = [mvc.Components.get("default"), mvc.Components.get("submitted")];

    function husk(navn, apen) {
        try { window.localStorage.setItem("lukkbar_" + navn, apen ? "1" : "0"); } catch (e) { /* ikke viktig */ }
    }

    function huskes(navn) {
        try { return window.localStorage.getItem("lukkbar_" + navn) === "1"; } catch (e) { return false; }
    }

    $("[id^='lukkbar_']").each(function () {
        var panel = $(this);
        var navn = this.id.replace("lukkbar_", "");
        var token = "vis_" + navn;
        var tittel = panel.find(".panel-title, h2").first();
        var pil = $("<span class='lukkbar-pil' aria-hidden='true'></span>").css({
            display: "inline-block", width: "1.2em", transition: "transform 0.15s"
        });
        tittel.prepend(pil).css({cursor: "pointer", userSelect: "none"})
            .attr({role: "button", tabindex: 0});

        function sett(apen) {
            tokens.forEach(function (t) {
                if (!t) { return; }
                if (apen) { t.set(token, "1"); } else { t.unset(token); }
            });
            pil.text("▶").css("transform", apen ? "rotate(90deg)" : "none");
            tittel.attr("aria-expanded", apen ? "true" : "false");
            husk(navn, apen);
        }

        function bytt() { sett(!tokens[0].get(token)); }

        tittel.on("click", bytt).on("keydown", function (e) {
            if (e.key === "Enter" || e.key === " ") { e.preventDefault(); bytt(); }
        });
        // Teksten «Trykk for å vise» i panelet åpner det også.
        panel.on("click", ".lukkbar-hint", function () { sett(true); });

        sett(huskes(navn));
    });
});
