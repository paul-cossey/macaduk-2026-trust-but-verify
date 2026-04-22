#!/usr/bin/env python3
"""
Generate the MacAD.UK 2026 "Trust, but Verify" presentation.
Cold War spy-themed slide deck.
"""

import os

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

from lxml import etree

# ── Colour palette ──────────────────────────────────────────────
FONT_NAME = "Courier New"
BG_DARK = RGBColor(0x0F, 0x0F, 0x0F)       # near-black
BG_CARD = RGBColor(0x1A, 0x1A, 0x2E)       # dark navy
ACCENT_RED = RGBColor(0xCC, 0x24, 0x24)    # Soviet red
ACCENT_AMBER = RGBColor(0xFF, 0xA5, 0x00)  # amber / caution
ACCENT_GREEN = RGBColor(0x00, 0xC8, 0x53)  # cleared green
TEXT_AMBER_DIM = RGBColor(0x6F, 0x4A, 0x00)     # dimmed amber
TEXT_WHITE = RGBColor(0xFF, 0xFF, 0xFF)
TEXT_LIGHT = RGBColor(0xCC, 0xCC, 0xCC)
TEXT_DIM = RGBColor(0x88, 0x88, 0x88)
STAMP_RED = RGBColor(0xCC, 0x00, 0x00)
STAMP_GREEN = RGBColor(0x00, 0x99, 0x33)

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)

prs = Presentation()
prs.slide_width = SLIDE_W
prs.slide_height = SLIDE_H

# ── Helper functions ────────────────────────────────────────────
def _set_slide_bg(slide, colour):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = colour


def _set_lang_en_gb(paragraph):
    """
    Set language to en-GB on all runs in a paragraph.
    """
    for run in paragraph.runs:
        run_props = run._r.get_or_add_rPr()
        run_props.set('lang', 'en-GB')
        run_props.set('altLang', 'en-GB')


def _add_textbox(slide, left, top, width, height, text, font_size=18,
                 colour=TEXT_WHITE, bold=False, alignment=PP_ALIGN.LEFT,
                 font_name=FONT_NAME):
    """
    Add a single-line textbox with the specified properties.
    """
    txbox = slide.shapes.add_textbox(left, top, width, height)
    tf = txbox.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    try:
        tf.paragraphs[0].alignment = alignment
    except Exception:
        pass
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = colour
    p.font.bold = bold
    p.font.name = font_name
    _set_lang_en_gb(p)
    try:
        txbox.text_frame.paragraphs[0].space_after = Pt(0)
        txbox.text_frame.paragraphs[0].space_before = Pt(0)
    except Exception:
        pass
    return txbox


def _add_multiline(slide, left, top, width, height, lines, font_size=18,
                   colour=TEXT_WHITE, bold=False, alignment=PP_ALIGN.LEFT,
                   font_name=FONT_NAME, line_spacing=1.3):
    """
    lines is a list of (text, colour, bold, font_size) tuples, plain strings, or lists of tuples.
    If a line is a list of tuples, they'll render on the same line with mixed formatting.
    """
    txbox = slide.shapes.add_textbox(left, top, width, height)
    tf = txbox.text_frame
    tf.word_wrap = True
    for i, line in enumerate(lines):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()

        # Check if line is a list of tuples (mixed formatting on same line)
        if isinstance(line, list):
            for j, run_spec in enumerate(line):
                txt = run_spec[0]
                clr = run_spec[1] if len(run_spec) > 1 else colour
                bld = run_spec[2] if len(run_spec) > 2 else bold
                fs = run_spec[3] if len(run_spec) > 3 else font_size

                if j == 0:
                    p.text = txt
                    r = p.runs[0]
                else:
                    r = p.add_run()
                    r.text = txt

                r.font.size = Pt(fs)
                r.font.color.rgb = clr
                r.font.bold = bld
                r.font.name = font_name
        else:
            # Original single-line logic
            if isinstance(line, str):
                txt, clr, bld, fs = line, colour, bold, font_size
            else:
                txt = line[0]
                clr = line[1] if len(line) > 1 else colour
                bld = line[2] if len(line) > 2 else bold
                fs = line[3] if len(line) > 3 else font_size
            p.text = txt
            p.font.size = Pt(fs)
            p.font.color.rgb = clr
            p.font.bold = bld
            p.font.name = font_name

        p.alignment = alignment
        p.space_after = Pt(int(font_size * (line_spacing - 1)))
        _set_lang_en_gb(p)
    return txbox


def _add_stamp(slide, text, left, top, colour=STAMP_RED, size=48, rotation=-12.0,
               width=Inches(5), height=Inches(1.4)):
    """
    Add a tilted 'CLASSIFIED' / 'CLEARED' style stamp.
    """
    w, h = width, height
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, w, h)
    shape.rotation = rotation
    shape.fill.background()
    shape.line.color.rgb = colour
    shape.line.width = Pt(4)
    tf = shape.text_frame
    tf.word_wrap = False
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(size)
    p.font.color.rgb = colour
    p.font.bold = True
    p.font.name = FONT_NAME
    p.alignment = PP_ALIGN.CENTER
    _set_lang_en_gb(p)
    return shape


def _add_divider(slide, top, colour=ACCENT_RED):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0.8), top, Inches(11.7), Pt(3))
    shape.fill.solid()
    shape.fill.fore_color.rgb = colour
    shape.line.fill.background()
    return shape


def _animate_slide(slide):
    """
    Add stamp zoom animation to rotated stamp shapes only.
    """
    P_NS = 'http://schemas.openxmlformats.org/presentationml/2006/main'

    stamp_shapes = []
    for shape in slide.shapes:
        if not (shape.has_text_frame and shape.text_frame.text.strip()):
            continue
        if abs(shape.rotation) > 0.5:
            stamp_shapes.append(shape)

    if not stamp_shapes:
        return

    stamp_shapes.sort(key=lambda s: (s.top, s.left))

    _c = [0]

    def nid():
        _c[0] += 1
        return _c[0]

    rid, sid, gid = nid(), nid(), nid()

    parts = []
    for i, shape in enumerate(stamp_shapes):
        sp = shape.shape_id
        nt = 'clickEffect' if i == 0 else 'afterEffect'
        a, b, c = nid(), nid(), nid()
        parts.append(
            f'<p:par><p:cTn id="{a}" presetID="53" presetClass="entr" '
            f'presetSubtype="16" fill="hold" nodeType="{nt}">'
            f'<p:stCondLst><p:cond delay="0"/></p:stCondLst>'
            f'<p:childTnLst><p:set><p:cBhvr>'
            f'<p:cTn id="{b}" dur="1" fill="hold">'
            f'<p:stCondLst><p:cond delay="0"/></p:stCondLst></p:cTn>'
            f'<p:tgtEl><p:spTgt spid="{sp}"/></p:tgtEl>'
            f'<p:attrNameLst><p:attrName>style.visibility</p:attrName>'
            f'</p:attrNameLst>'
            f'</p:cBhvr><p:to><p:strVal val="visible"/></p:to></p:set>'
            f'<p:animScale><p:cBhvr>'
            f'<p:cTn id="{c}" dur="200" decel="80000" fill="hold"/>'
            f'<p:tgtEl><p:spTgt spid="{sp}"/></p:tgtEl>'
            f'</p:cBhvr><p:from x="200000" y="200000"/>'
            f'<p:to x="100000" y="100000"/></p:animScale>'
            f'</p:childTnLst></p:cTn></p:par>'
        )

    inner = ''.join(parts)
    xml = (
        f'<p:timing xmlns:p="{P_NS}"><p:tnLst><p:par>'
        f'<p:cTn id="{rid}" dur="indefinite" restart="never" nodeType="tmRoot">'
        f'<p:childTnLst><p:seq concurrent="1" nextAc="seek">'
        f'<p:cTn id="{sid}" dur="indefinite" nodeType="mainSeq">'
        f'<p:childTnLst><p:par><p:cTn id="{gid}" fill="hold">'
        f'<p:stCondLst><p:cond delay="0"/></p:stCondLst>'
        f'<p:childTnLst>{inner}</p:childTnLst>'
        f'</p:cTn></p:par></p:childTnLst></p:cTn>'
        f'<p:prevCondLst><p:cond evt="onPrev" delay="0">'
        f'<p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:prevCondLst>'
        f'<p:nextCondLst><p:cond evt="onNext" delay="0">'
        f'<p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:nextCondLst>'
        f'</p:seq></p:childTnLst></p:cTn>'
        f'</p:par></p:tnLst></p:timing>'
    )
    slide._element.append(etree.fromstring(xml))


# ── Slide builders ──────────────────────────────────────────────
def slide_title(prs):
    """
    Slide 1 — Title card.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.5), Inches(0.4), Inches(12), Inches(0.5),
                 "▒▒▒  CLASSIFIED  ▒▒▒", 16, TEXT_DIM, font_name=FONT_NAME,
                 alignment=PP_ALIGN.CENTER)

    _add_textbox(slide, Inches(0.8), Inches(1.2), Inches(11.7), Inches(1.5),
                 '"TRUST, BUT VERIFY"', 60, TEXT_WHITE, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_divider(slide, Inches(2.8))

    _add_textbox(slide, Inches(0.8), Inches(3.1), Inches(11.7), Inches(1.2),
                 "Building a Software Safety Snapshot\nBefore Deploying to Your Fleet",
                 30, TEXT_LIGHT, alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_textbox(slide, Inches(0.8), Inches(4.8), Inches(11.7), Inches(0.6),
                 "MacAD.UK  ·  2026", 22, ACCENT_RED, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_textbox(slide, Inches(0.8), Inches(5.5), Inches(11.7), Inches(0.6),
                 "AGENTS: Toms & Cossey",
                 20, TEXT_DIM, alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_textbox(slide, Inches(0.8), Inches(6.4), Inches(11.7), Inches(0.6),
                 'довеpяй, но провеpяй', 16, TEXT_DIM,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('BT - Introduce the presentation as a top-secret briefing on software '
                       'safety, inspired by Cold War spy themes. Emphasise the importance of '
                       '`Trust, but Verify` in the context of Mac administration and software '
                       'deployment.')

def slide_agents(prs):
    """
    Slide 2 — Who we are (agent dossiers).
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "AGENT DOSSIERS", 44, ACCENT_RED, True,
                 alignment=PP_ALIGN.LEFT, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    # Ben — card border (left, alphabetical first)
    card_l, card_t, card_w, card_h = Inches(0.8), Inches(1.5), Inches(5.5), Inches(4.8)
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, card_l, card_t, card_w, card_h)
    shape.fill.background()
    shape.line.color.rgb = TEXT_DIM
    shape.line.width = Pt(1.5)

    _add_multiline(slide, Inches(1.2), Inches(1.7), Inches(4.8), Inches(4.3), [
        ("AGENT", TEXT_DIM, False, 14),
        ("Ben Toms", TEXT_WHITE, True, 28),
        ('', TEXT_DIM, False, 8),
        ("ROLE", TEXT_DIM, False, 14),
        ("Principal Software Engineer", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 8),
        ("ORG", TEXT_DIM, False, 14),
        ("Jamf", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 8),
        ("CLEARANCE", TEXT_DIM, False, 14),
        ("████████████", TEXT_DIM, False, 22),
        ('', TEXT_DIM, False, 8),
        ("STATUS: ACTIVE", ACCENT_GREEN, True, 20),
    ], font_name=FONT_NAME)

    # REDACTED stamp over Ben's clearance
    _add_stamp(slide, "REDACTED", Inches(1.34), Inches(5.33), STAMP_RED, 28, -6,
               width=Inches(1.89), height=Inches(0.55))

    # Paul — card border (right)
    card_l2 = Inches(7.0)
    shape2 = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, card_l2, card_t, card_w, card_h)
    shape2.fill.background()
    shape2.line.color.rgb = TEXT_DIM
    shape2.line.width = Pt(1.5)

    _add_multiline(slide, Inches(7.4), Inches(1.65), Inches(4.8), Inches(4.3), [
        ("AGENT", TEXT_DIM, False, 14),
        ("Paul Cossey", TEXT_WHITE, True, 28),
        ('', TEXT_DIM, False, 8),
        ("ROLE", TEXT_DIM, False, 14),
        ("Client Platform", TEXT_LIGHT, False, 22),
        ("Engineer", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 8),
        ("ORG", TEXT_DIM, False, 14),
        ("Jamf", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 8),
        ("CLEARANCE", TEXT_DIM, False, 14),
        ("████████████", TEXT_DIM, False, 22),
        ('', TEXT_DIM, False, 8),
        ("STATUS: ACTIVE", ACCENT_GREEN, True, 20),
    ], font_name=FONT_NAME)

    # REDACTED stamp over Paul's clearance
    _add_stamp(slide, "REDACTED", Inches(7.48), Inches(5.33), STAMP_RED, 28, -6,
               width=Inches(2.02), height=Inches(0.57))

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'BT - Introduce ourselves as the agents behind this '
        'operation. Use the dossier format to playfully present our '
        'roles, organisations, and top-secret clearance levels. The '
        'REDACTED stamps add a fun touch of mystery and intrigue.\n'
        '\n'
        'PC \u2013 Hello, I\u2019m Paul, and I\u2019m a Client Platform '
        'Engineer at Jamf., and I work on the Jamf Auto Update '
        'product.\n'
        '\n'
        'Like all good straight-to-Betamax spy thrillers, my origin '
        'story starts deep undercover\u2026 Sorting mail in the '
        'Virgin Direct Postroom in the late 90\u2019s - I know what '
        'you\u2019re thinking, and, yes, I really am that old!\n'
        '\n'
        'I\u2019d always had an interest in computers so, when I '
        'discovered that helpdesk teams were a thing; I made the '
        'decision that was the career for me. But other than '
        'completing Doom and Quake I had no real-world IT experience '
        'to get myself there, so I volunteered my free time for '
        'hardware rebuilds, and office moves during a site wide network upgrade '
        'from Token Ring to Ethernet to get some experience.\n'
        '\n'
        'This led on to a secondment to the helpdesk, which then '
        'turned into a permanent role.\n'
        '\n'
        'The first 10 years or so were Windows-based with '
        'roles at Norfolk County Council, James Paget Hospital '
        'and Great Yarmouth & Waveney PCT - in 2006 I joined '
        'Cambridge Education Group, where there was a small but '
        'quickly growing Apple Mac estate, it was there that I began to drift '
        'from Microsoft to Apple.\n'
        '\n'
        'From Cambridge Education Group my next role was much '
        'closer to home at Norwich University of the Arts, where I '
        'spent eleven years as the technical owner of the Apple '
        'estate.\n'
        '\n'
        'As we were coming out of the pandemic, I applied for a '
        'role at dataJAR to work on the Auto Update product, '
        'and somehow managed to convince Ben and Yannis that I was '
        'the man for the job, a decision I\u2019m sure they regret '
        'at least every other day. Sorry about that!\n'
        '\n'
        'dataJAR was then acquired by Jamf, and I moved over to '
        'continue work on the rebranded Jamf Auto Update product in '
        'the App Lifecycle and Software Update teams.'
    )


def slide_jamf_auto_update(prs):
    """
    Slide 3 — Jamf Auto Update summary.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "JAMF AUTO UPDATE", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(11.5), Inches(5.5), [
        ("Automated application packaging and deployment", TEXT_WHITE, True, 26),
        ("service for Jamf Pro", TEXT_WHITE, True, 26),
        ('', TEXT_DIM, False, 10),
        ("1k+ macOS software titles", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 6),
        ("  ✓  App Store-like update experience for 3rd party apps", ACCENT_GREEN, False, 20),
        ("  ✓  Cloud-based, managed patch definitions for Jamf Pro", ACCENT_GREEN, False, 20),
        ("  ✓  Native Notification Centre integration", ACCENT_GREEN, False, 20),
        ('', TEXT_DIM, False, 10),
        ("ENHANCED SECURITY & PACKAGE VALIDATION:", ACCENT_RED, True, 20),
        ('', TEXT_DIM, False, 4),
        ("  Titles pass Developer Signing Certificate checks,", TEXT_LIGHT, False, 20),
        ("  SHA-256 verification, and VirusTotal analysis", TEXT_LIGHT, False, 20),
        ("  before release to production.", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 10),
        ("datajar.co.uk/products/jamf-auto-update", ACCENT_AMBER, True, 18),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'BT \u2013 So what is Jamf Auto Update? It\u2019s an automated '
        'application packaging and deployment service for Jamf Pro. It '
        'provides over 1,000 macOS software titles, with an App '
        'Store-like update experience for third-party applications '
        'outside of the Mac App Store.\n\n'
        'It integrates natively with Jamf Pro patch management and '
        'includes native Notification Centre integration so users get '
        'notified of pending and completed updates.\n\n'
        'Critically for this talk, titles are not released into '
        'production until they\u2019ve passed a number of security '
        'checks \u2013 Developer Signing Certificate verification, '
        'SHA-256 checks, and VirusTotal analysis. That\u2019s the '
        'process we\u2019re going to dive into today.')


def slide_reagan_quote(prs):
    """
    Slide 4 — The Reagan quote & origin."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "ORIGIN", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_textbox(slide, Inches(1.5), Inches(1.8), Inches(10), Inches(2.0),
                 '"Trust, but verify."', 52, TEXT_WHITE, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_textbox(slide, Inches(1.5), Inches(3.5), Inches(10), Inches(0.6),
                 "— Ronald Reagan, 1987  (INF Treaty signing)", 22, TEXT_DIM,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_multiline(slide, Inches(1.2), Inches(4.5), Inches(10.5), Inches(2.5), [
        ('Russian proverb:  "довеpяй, но провеpяй"', TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 10),
        ("Reagan used it so often that Gorbachev once replied:", TEXT_LIGHT, False, 20),
        ('"You repeat that at every meeting!"', ACCENT_AMBER, True, 22),
        ('', TEXT_DIM, False, 10),
        ("Today: the foundation of Zero Trust security models.", TEXT_LIGHT, False, 20),
    ], font_name=FONT_NAME, alignment=PP_ALIGN.LEFT)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 So, \u201cTrust, but verify\u201d \u2013 it\u2019s '
        'a phrase you\u2019re probably more used to hearing in the '
        'identity space, but it\u2019s actually an old Russian '
        'proverb. It rhymes in Russian: \u201cdoveryay, no '
        'proveryay\u201d.\n'
        '\n'
        'The phrase became internationally known thanks to an '
        'American scholar called Suzanne Massie, she met with '
        "Reagan many times between '84 and '87, and taught him "
        'the proverb and told him: \u201cThe Russians like to talk '
        'in proverbs. It would be nice of you to know a few. You '
        'are an actor \u2013 you can learn them very '
        'quickly.\u201d\n'
        '\n'
        'Reagan loved it and adopted it as his signature phrase '
        'when discussing relations with the Soviet Union. He used '
        'it so often that at the signing of the INF Treaty on 8th '
        'December 1987, Gorbachev finally replied: \u201cYou repeat '
        'that at every meeting!\u201d Reagan\u2019s response was '
        '\u201cI like it.\u201d\n'
        '\n'
        'As a fun side note: while Reagan was quoting Russian '
        'proverbs, Gorbachev was quoting Ralph Waldo Emerson back '
        'at him \u2013 \u201cThe reward of a thing well done is to '
        'have done it.\u201d Emerson had apparently been popular in '
        'the USSR when Gorbachev was at university.\n'
        '\n'
        'The phrase has had a long afterlife too. In 2001, the '
        'National Infrastructure Protection Center published a '
        'paper called \u201cTrust but verify\u201d about protecting '
        'yourself from email viruses. In 2013, John Kerry updated '
        'it for the Syria chemical weapons deal, saying '
        'Reagan\u2019s old adage was \u201cin need of an '
        'update\u201d and that they\u2019d committed to a standard '
        'of \u201cverify and verify.\u201d In 2020, Pompeo went '
        'even further, saying the US should \u201cdistrust and '
        'verify\u201d when dealing with China.\n'
        '\n'
        'But for many in IT today, it\u2019s the foundation of Zero Trust '
        'security models \u2013 and the perfect lens for thinking '
        'about how we verify software before it hits our fleets.'
    )


def slide_links(prs):
    """
    Slide 3 — Links and resources.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.4), Inches(11.7),
        Inches(0.8), "START OF BRIEFING", 44, ACCENT_RED,
        True, alignment=PP_ALIGN.CENTER,
        font_name=FONT_NAME)

    _add_divider(slide, Inches(1.3))

    # Spy duck animated GIF
    gif_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'spy_duck_peek.gif')
    if os.path.exists(gif_path):
        gif_w = Inches(12.57)
        gif_h = Inches(5.44)
        gif_left = (SLIDE_W - gif_w) // 2
        slide.shapes.add_picture(
            gif_path, gif_left, Inches(1.63),
            gif_w, gif_h)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC and BT \u2013 Secret agent duck animation'
    )


def slide_poll_results(prs):
    """
    Slide 5 — Poll results.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "FIELD INTELLIGENCE", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_textbox(slide, Inches(0.8), Inches(1.4), Inches(11.5), Inches(0.8),
                 "What clearance level do you use before 3rd party\n"
                 "software deploys to your fleet?",
                 24, TEXT_WHITE, True, font_name=FONT_NAME)

    levels = [
        ("Level 0", "Blind Trust",
         "The vendor said it's safe. Ship it.", ACCENT_RED),
        ("Level 1", "Quick Pat-Down",
         "Install it, check it launches.", ACCENT_AMBER),
        ("Level 2", "Entry & Exit Check",
         "Test install and uninstall.", ACCENT_AMBER),
        ("Level 3", "Interrogation",
         "Install + run through security tools.", ACCENT_GREEN),
        ("Level 4", "Full Dossier",
         "Install, monitor, scan, profile, uninstall, report.", ACCENT_GREEN),
    ]

    y = Inches(2.8)
    bar_max_w = Inches(7.0)
    bar_h = Inches(0.45)
    placeholder_widths = [0.09, 0.26, 0.39, 0.22, 0.04]

    for i, (level, name, desc, clr) in enumerate(levels):
        _add_textbox(slide, Inches(0.8), y, Inches(4.5), Inches(0.35),
                     f"{level}: {name}", 18, clr, True, font_name=FONT_NAME)
        _add_textbox(slide, Inches(0.8), y + Inches(0.35), Inches(4.5), Inches(0.3),
                     desc, 14, TEXT_DIM, font_name=FONT_NAME)

        bar_w = int(bar_max_w * placeholder_widths[i])
        if bar_w > 0:
            bar = slide.shapes.add_shape(
                MSO_SHAPE.RECTANGLE, Inches(5.8),
                y + Inches(0.05), bar_w, bar_h)
            bar.fill.solid()
            bar.fill.fore_color.rgb = clr
            bar.line.fill.background()

        pct = f"{int(placeholder_widths[i] * 100)}%"
        _add_textbox(slide, Inches(5.8) + max(bar_w, 0) + Inches(0.15),
                     y + Inches(0.05), Inches(1.0), bar_h,
                     pct, 18, TEXT_DIM, font_name=FONT_NAME)

        y += Inches(0.85)

    _add_textbox(slide, Inches(0.8), Inches(7.0), Inches(11.5), Inches(0.4),
                 "// 23 responses", 14, TEXT_DIM,
                 font_name=FONT_NAME)
    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 So, we ran a session poll in the Whova App, '
        'and there\u2019s been some encouraging responses - looks '
        'like most of you are already doing some level of '
        'verification before deploying, which is great!\n'
        '\n'
        'We\u2019ve even got someone at Level 4 already! Hopefully '
        'by the end of this session, we can convince a few more '
        'of you to go for the full dossier!'
    )


def slide_the_problem(prs):
    """
    Slide 6 — Why this matters.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "THE THREAT LANDSCAPE", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(11.5), Inches(5.5), [
        ("Deploying software is a core Mac Admin responsibility.", TEXT_WHITE, False, 24),
        ('', TEXT_DIM, False, 10),
        ("But software can get compromised:", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 8),
        ("  \u26a0  XcodeGhost \u2014 infected IDE distributed via China (2015)",
         ACCENT_AMBER, False, 22),
        ("  \u26a0  KeRanger \u2014 ransomware trojan horse (2016)",
         ACCENT_AMBER, False, 22),
        ("  \u26a0  HandBrake \u2014 trojanised download mirror (2017)",
         ACCENT_AMBER, False, 22),
        ("  \u26a0  Codecov \u2014 bash uploader tampered for months (2021)",
         ACCENT_AMBER, False, 22),
        ("  \u26a0  Axios \u2014 supply chain attack (2026)",
         ACCENT_AMBER, False, 22),
        ('', TEXT_DIM, False, 10),
        ("Trusting a vendor alone is not enough.", TEXT_WHITE, True, 26),
        ('', TEXT_DIM, False, 8),
        ("You need to verify every asset before it enters the homeland.", ACCENT_GREEN, False, 22),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'BT - So most of you are already doing some '
        'level of checking, which is great. But '
        'let\'s look at why even that might not be '
        'enough. Here are some real-world examples '
        'of supply chain attacks where software was '
        'compromised before it reached you.\n'
        '\n'
        'Blog posts / sources for reference:\n'
        '  XcodeGhost: unit42.paloaltonetworks.com/'
        'novel-malware-xcodeghost-modifies-xcode-'
        'infects-apple-ios-apps\n'
        '  KeRanger: unit42.paloaltonetworks.com/'
        'new-os-x-ransomware-keranger-infected-'
        'transmission-bittorrent-client-installer\n'
        '  HandBrake: objective-see.org/blog/'
        'blog_0x1D.html\n'
        '  Codecov: about.codecov.io/'
        'security-update\n'
        '  General supply chain: objective-see.org/'
        'blog/blog_0x75.html'
    )


def slide_code_signature_verification(prs):
    """
    Slide 7 — Why this matters. Expanded with code signature verification focus.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "THE THREAT LANDSCAPE", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(11.5), Inches(5.5), [
        ("Deploying software is a core Mac Admin responsibility.", TEXT_WHITE, False, 24),
        ('', TEXT_DIM, False, 10),
        ("But software can get compromised:", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 8),
        ("  ⚠  XcodeGhost — infected IDE distributed via China (2015)", ACCENT_AMBER, False, 22),
        ("  ⚠  KeRanger — ransomware trojan horse (2016)", ACCENT_AMBER, False, 22),
        ("  ⚠  HandBrake — trojanised download mirror (2017)", ACCENT_AMBER, False, 22),
        ("  ⚠  Codecov — bash uploader tampered for months (2021)", TEXT_AMBER_DIM, False, 22),
        ("  ⚠  Axios — supply chain attack (2026)", TEXT_AMBER_DIM, False, 22),
        ('', TEXT_DIM, False, 10),
        ("Trusting a vendor alone is not enough.", TEXT_WHITE, True, 26),
        ('', TEXT_DIM, False, 8),
        ("You need to verify every asset before it enters the homeland.", ACCENT_GREEN, False, 22),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('BT - These first three examples (XcodeGhost, KeRanger, HandBrake) were '
                       'cases where code signature verification would have failed because the '
                       'software was tampered with before it was signed.')


def slide_code_signature_verification_example_1(prs):
    """
    Slide 8 — Examples of how to verify code signatures, and some open source tools that
    leverage this approach.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "CODE SIGNATURE VERIFICATION", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3), Inches(11.5), Inches(5.5), [
        ("codesign --display -r- --deep -v \"/Applications/Google Chrome.app\"", ACCENT_GREEN, False,
         18),
        ('', TEXT_DIM, False, 8),
        ('Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', TEXT_WHITE, False,
         16),
        ('Identifier=com.google.Chrome', TEXT_WHITE, False, 16),
        ('Format=app bundle with Mach-O universal (x86_64 arm64)', TEXT_WHITE, False, 16),
        ('CodeDirectory v=20500 size=893 flags=0x12a00(kill,restrict,library-validation,runtime) '
         'hashes=17+7 location=embedded', TEXT_WHITE, False, 16),
        ('Signature size=8989', TEXT_WHITE, False, 16),
        ('Timestamp=6 Apr 2026 at 21:44:58', TEXT_WHITE, False, 16),
        ('Info.plist entries=45', TEXT_WHITE, False, 16),
        [('TeamIdentifier=', TEXT_WHITE, False, 16), ('EQHXZ8M8AV', ACCENT_AMBER, False, 16)],
        ('Runtime Version=26.2.0', TEXT_WHITE, False, 16),
        ('Sealed Resources version=2 rules=13 files=63', TEXT_WHITE, False, 16),
        ('Nested=Frameworks/Google Chrome Framework.framework', TEXT_WHITE, False, 16),
        [('designated => (identifier "com.google.Chrome" or identifier "com.google.Chrome.beta" or '
          'identifier "com.google.Chrome.dev" or identifier "com.google.Chrome.canary") and anchor '
          'apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
          'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate '
          'leaf[subject.OU] = ', TEXT_WHITE, False, 16), ('EQHXZ8M8AV', ACCENT_AMBER, False, 16)],
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('BT - These first three examples (XcodeGhost, KeRanger, HandBrake) were '
                       'cases where code signature verification would have failed because the '
                       'software was tampered with before it was signed.')


def slide_code_signature_verification_example_2(prs):
    """
    Slide 9 — Examples of how to verify code signatures, and some open source tools that
    leverage this approach.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "CODE SIGNATURE VERIFICATION", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3), Inches(11.5), Inches(5.5), [
        ('pkgutil --check-signature /Users/ronald/Downloads/JamfAutoUpdate-1.5.pkg',
         ACCENT_GREEN, False,
         18),
        ('', TEXT_DIM, False, 8),
        ('Package \"JamfAutoUpdate-1.5.pkg\":', TEXT_WHITE, False, 16),
        ('\tStatus: signed by a developer certificate issued by Apple for distribution',
         TEXT_WHITE, False, 16),
        ('\tNotarization: trusted by the Apple notary service', TEXT_WHITE, False, 16),
        ('\tSigned with a trusted timestamp on: 2026-04-08 12:33:51 +0000', TEXT_WHITE, False, 16),
        ('\tCertificate Chain:', TEXT_WHITE, False, 16),
        [('    1.  Developer ID Installer: JAMF Software (', TEXT_WHITE, False, 16), ('483DWKW443',
            ACCENT_AMBER, False, 16), (')', TEXT_WHITE, False, 16)],
        ('        Expires: 2027-06-01 16:58:54 +0000', TEXT_WHITE, False, 16),
        ('        SHA256 Fingerprint:', TEXT_WHITE, False, 16),
        ('\t\t\t CB 3C 51 9C E7 9B 47 8D 81 4A C7 FA 17 46 36 1F 9F 3C F9 5A 7B 48', TEXT_WHITE,
         False, 16),
        ('\t\t\t 92 E7 DF 0B 58 DD E1 EE 1B DD', TEXT_WHITE, False, 16),
        ('\t\t------------------------------------------------------------------------',
         TEXT_WHITE, False, 16),
        ('    2.  Developer ID Certification Authority', TEXT_WHITE, False, 16),
        ('        Expires: 2031-09-17 00:00:00 +0000', TEXT_WHITE, False, 16),
        ('        SHA256 Fingerprint:', TEXT_WHITE, False, 16),
        ('\t\t\t F1 6C D3 C5 4C 7F 83 CE A4 BF 1A 3E 6A 08 19 C8 AA A8 E4 A1 52 8F', TEXT_WHITE,
         False, 16),
        ('\t\t\t D1 44 71 5F 35 06 43 D2 DF 3A', TEXT_WHITE, False, 16),
        ('\t\t------------------------------------------------------------------------',
         TEXT_WHITE, False, 16),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('BT - These first three examples (XcodeGhost, KeRanger, HandBrake) were '
                       'cases where code signature verification would have failed because the '
                       'software was tampered with before it was signed.')


def slide_code_signature_verification_example_3(prs):
    """
    Slide 10 — Examples of how to verify code signatures, and notarisation status, via spctl.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "CODE SIGNATURE VERIFICATION", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3), Inches(11.5), Inches(5.5), [
        ('spctl -a -vv \"/Applications/Google Chrome.app\"', ACCENT_GREEN, False,
         18),
        ('', TEXT_DIM, False, 8),
        ('/Applications/Google Chrome.app: accepted', TEXT_WHITE, False,
         16),
        ('source=Notarized Developer ID', TEXT_WHITE, False, 16),
        [('origin=Developer ID Application: Google LLC (', TEXT_WHITE, False, 16),
         ('EQHXZ8M8AV',ACCENT_AMBER, False, 16), (')', TEXT_WHITE, False, 16)],
    ], font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(4.0), Inches(11.5), Inches(5.5), [
        ("spctl -a -vv -t install /Users/ronald/Downloads/JamfAutoUpdate-1.5.pkg", ACCENT_GREEN, False,
         18),
        ('', TEXT_DIM, False, 8),
        ('/Users/ronald/Downloads/JamfAutoUpdate-1.5.pkg', TEXT_WHITE, False,
         16),
        ('source=Notarized Developer ID', TEXT_WHITE, False, 16),
        [('origin=Developer ID Application: JAMF Software (', TEXT_WHITE, False, 16),
         ('483DWKW443',ACCENT_AMBER, False, 16), (')', TEXT_WHITE, False, 16)],
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('BT - These first three examples (XcodeGhost, KeRanger, HandBrake) were '
                       'cases where code signature verification would have failed because the '
                       'software was tampered with before it was signed.')


def slide_the_evolving_problem(prs):
    """
    Slide 12 — Why this matters (evolving problem).
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "THE THREAT LANDSCAPE", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(11.5), Inches(5.5), [
        ("Deploying software is a core Mac Admin responsibility.", TEXT_WHITE, False, 24),
        ('', TEXT_DIM, False, 10),
        ("But software can get compromised:", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 8),
        ("  ⚠  XcodeGhost — infected IDE distributed via China (2015)", TEXT_AMBER_DIM, False, 22),
        ("  ⚠  KeRanger — ransomware trojan horse (2016)", TEXT_AMBER_DIM, False, 22),
        ("  ⚠  HandBrake — trojanised download mirror (2017)", TEXT_AMBER_DIM, False, 22),
        ("  ⚠  Codecov — bash uploader tampered for months (2021)", ACCENT_AMBER, False, 22),
        ("  ⚠  Axios — supply chain attack (2026)", ACCENT_AMBER, False, 22),
        ('', TEXT_DIM, False, 10),
        ("Trusting a vendor alone is not enough.", TEXT_WHITE, True, 26),
        ('', TEXT_DIM, False, 8),
        ("You need to verify every asset before it enters the homeland.", ACCENT_GREEN, False, 22),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('BT - Discuss the limitations of relying solely on code signature '
                       'verification as a security measure. Use the examples of real-world supply '
                       'chain attacks to illustrate how even signed software can be compromised. '
                       'Emphasise the need for a more comprehensive approach to verifying software safety.')


def slide_mission_brief_history(prs):
    """
    Slide 13 — How our process evolved.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "INTELLIGENCE HISTORY", 44, ACCENT_RED, True,
                 font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    # Evolution bullet points (full width)
    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(11.5),
        Inches(2.5), [
            ("The evolution of our verification process:",
             TEXT_WHITE, False, 20),
            ('', TEXT_DIM, False, 6),
            ("  Inherited basic checks", TEXT_LIGHT, False, 18),
            ("  Code signature validation and VirusTotal",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 4),
            ("  Objective-See tools on test devices",
             TEXT_LIGHT, False, 18),
            ("  Manual observation for suspicious behaviour",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 4),
            ("  The checklist", ACCENT_AMBER, False, 18),
            ("  Structured, repeatable process for "
             "every title.",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME)

    # The catalyst
    _add_textbox(
        slide, Inches(0.9), Inches(4.27), Inches(11.5),
        Inches(0.5),
        (" Posts like this made us question"
         " whether basic checks were enough:"),
        18, TEXT_DIM, font_name=FONT_NAME)

    # Blog post screenshot — centred, correct ratio
    # Image is 2030x750 → ratio ~2.7:1
    script_dir = os.path.dirname(os.path.abspath(__file__))
    blog_img = os.path.join(script_dir, 'lockbit_virustotal.png')
    if os.path.exists(blog_img):
        slide.shapes.add_picture(
            blog_img, Inches(3.44), Inches(4.77),
            Inches(6.06), Inches(2.24))

    _add_textbox(
        slide, Inches(0.8), Inches(7.1), Inches(11.5),
        Inches(0.4),
        ("\u201cThe LockBit ransomware (kinda) comes for"
         " macOS\u201d  \u2014  objective-see.org/blog/"
         "blog_0x75.html"),
        12, TEXT_DIM, font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 Before I joined dataJAR, Ben was already '
        'doing code signature verification and VirusTotal '
        'checks on new titles. And I followed in those '
        'footsteps but got increasingly concerned about '
        'the risk of inadvertently adding compromised '
        'software to the catalog.\n'
        '\n'
        'Blog posts like Objective-See\u2019s - \u201cThe LockBit '
        'ransomware (kinda) comes for macOS\u201d really drove '
        'it home \u2013 because VirusTotal initially didn\u2019t '
        'flag anything untoward with the '
        '"locker_Apple_M1_64" sample.\n'
        '\n'
        'I\u2019d  noticed a pattern in Patrick blog posts. '
        'His tools seemed to stop a lot of previously '
        'unknow malware with no specific knowledge of '
        'them before hand.\n'
        '\n'
        'So, I added the some of Objective-See tools to '
        'my test devices and just started observing for '
        'suspicious behavior during installs. That then '
        'evolved into a checklist that I\u2019d fill out for '
        'every title and attached to the new title '
        'request ticket. ')


def slide_mission_brief_checklist(prs):
    """
    Slide 14 — The old checklist screenshots.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "THE CHECKLIST", 44, ACCENT_RED, True,
                 font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Top screenshot (left side)
    top_img = os.path.join(script_dir, 'checklist_top.png')
    if os.path.exists(top_img):
        slide.shapes.add_picture(
            top_img, Inches(0.3), Inches(1.4), Inches(6.2), Inches(5.8))

    # Bottom screenshot (right side)
    bottom_img = os.path.join(script_dir, 'checklist_bottom.png')
    if os.path.exists(bottom_img):
        slide.shapes.add_picture(
            bottom_img, Inches(6.8), Inches(1.4), Inches(6.2), Inches(5.8))

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 And this is the checklist. I used it as '
        'an installation test snapshot it covered a bunch '
        'things I would sometimes forget to add to '
        'recipes, a link to VirusTotal, code signing, '
        'screenshots of tiggered Objective-See tool '
        'results, what config profiles the title needed, '
        'whether a pkg had deprecated dependencies like  '
        'Python 2 in its scripts.\n'
        '\n'
        'With the pace of new titles requests we\u2019d '
        'receive, this process was manageable, but it was '
        'a bit of a faff filling it out, making sure we '
        'get all the screenshots and command output. It '
        'was  as prone to human error. as super easy to '
        'forget to take a screenshot or check something '
        'off the list, the Irony that I created it in '
        'the hope it would stop me forgetting things '
        'isn\u2019t lost me! ')


def slide_mission_brief(prs):
    """
    Slide 15 — The mission / our approach.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "MISSION BRIEFING", 44, ACCENT_RED, True,
                 font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_textbox(
        slide, Inches(0.8), Inches(1.4), Inches(11), Inches(0.8),
        ("Before any title enters Jamf Auto Update, "
         "we build\na safety snapshot of the asset."),
        24, TEXT_WHITE, font_name=FONT_NAME)

    _add_multiline(
        slide, Inches(0.8), Inches(2.6), Inches(11.5),
        Inches(4.27), [
            ("OPERATION PHASES:", ACCENT_RED, True, 20),
            ('', TEXT_DIM, False, 4),
            ("  1 \u2591  PROFILE         "
             "\u2014 Collect system data and state, "
             "tool details",
             TEXT_LIGHT, False, 18),
            ("  2 \u2591  MONITOR         "
             "\u2014 Start real-time surveillance",
             TEXT_LIGHT, False, 18),
            ("  3 \u2591  SCAN            "
             "\u2014 Run the asset through intelligence "
             "systems", TEXT_LIGHT, False, 18),
            ("  4 \u2591  INSTALL         "
             "\u2014 Deploy the asset in isolation",
             TEXT_LIGHT, False, 18),
            ("  5 \u2591  ANALYSE         "
             "\u2014 Inspect the asset and monitor "
             "behaviour",
             TEXT_LIGHT, False, 18),
            ("  6 \u2591  UNINSTALL       "
             "\u2014 Remove the asset & verify clean "
             "extraction", TEXT_LIGHT, False, 18),
            ("  7 \u2591  STOP MONITORING "
             "\u2014 Stand down real-time surveillance",
             TEXT_LIGHT, False, 18),
            ("  8 \u2591  REPORT          "
             "\u2014 Compile the full dossier",
             TEXT_LIGHT, False, 18),
            ("  9 \u2591  DECIDE          "
             "\u2014 Clear or reject",
             TEXT_LIGHT, False, 18),
            ('', TEXT_DIM, False, 4),
            ('', TEXT_DIM, False, 4),
            ("All using open-source and free-to-use "
             "tools.", ACCENT_GREEN, False, 18),
        ], font_name=FONT_NAME, line_spacing=1.15)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 So what do we do now? Well last summer we '
        'had a batch of about 20 or so new title requests '
        'come in at once, and the thought of running though '
        'the checklist one after the other kinda filled me '
        'with dread! \n\n'
        'I\u2019d had the idea to write a script to automate '
        'a lot of the testing process, but knew it would be '
        'quite a complicated task, so it stayed just an idea '
        'for a while, but thankfully this batch of new title '
        'requests coincided with the release of a new '
        'internal AI tool called Ask Jamf. I figured this '
        'was the perfect opportunity to test out the new '
        'tech and write the orchestration script I\u2019d had '
        'whirring in the back of my mind. I have now '
        'migrated to using copilot agents and Claude, which '
        'is much quicker and easier than the copy and '
        'pasting I was '
        'originally doing with Ask Jamf! \n\n'
        'When we test titles we ALWAYS test on actual '
        'hardware, and we test on both Apple Silicon and '
        'Intel. Although I\u2019m a great believer in any '
        'testing is better than no testing! One of the main '
        'reasons we test on hardware is malware '
        'authors are sneaky buggers, they\u2019ll often '
        'check to see if their code is being executed in a '
        'VM or a sandbox and then bail before anything '
        'malicious runs  in an '
        'attempt to avoid discovery by security '
        'researchers. \n\n'
        'So, what does the script do?')


def slide_toolbelt(prs):
    """
    Slide 16 — The tools overview.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "FIELD EQUIPMENT", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    rows = [
        ("DIVISION", "EQUIPMENT", "CODENAME", True, ACCENT_RED),
        ("─" * 20, "─" * 30, "─" * 20, False, TEXT_DIM),
        ("Malware Intel", "VirusTotal", "70+ intel agencies", False, TEXT_LIGHT),
        ("Binary Polygraph", "Jamf ThreatLabs", "Mach-O deep scan", False, TEXT_LIGHT),
        ("Sleeper Detection", "KnockKnock", "Persistence sweep", False, TEXT_LIGHT),
        ("Counter-Surveillance", "BlockBlock", "Persistence alerts", False, TEXT_LIGHT),
        ("Comms Intercept", "LuLu", "Network monitoring", False, TEXT_LIGHT),
        ("Border Security", "XProtect", "Apple's own guard", False, TEXT_LIGHT),
        ("Ransom Watch", "RansomWhere", "Encryption detection", False, TEXT_LIGHT),
        ("Audio/Visual", "OverSight", "Camera / mic watch", False, TEXT_LIGHT),
        ("Keylogger Sweep", "ReiKey", "Keyboard events", False, TEXT_LIGHT),
        ("Supply Chain", "DHS", "Dylib hijack scan", False, TEXT_LIGHT),
        ("Pkg Inspection", "pkgcheck", "Deprecated deps scan", False, TEXT_LIGHT),
        ("Orchestration", "Title Tester", "The handler (Python)", False, ACCENT_GREEN),
    ]

    y = Inches(1.4)
    for div, equip, code, is_bold, clr in rows:
        line = f"  {div:<22} {equip:<32} {code}"
        _add_textbox(slide, Inches(0.6), y, Inches(12), Inches(0.4),
                     line, 17, clr, is_bold, font_name=FONT_NAME)
        y += Inches(0.42)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 These tools form the security '
        'backbone, lets take a closer look at each')


def slide_objective_see(prs):
    """
    Slide 17 — Objective-See shout-out.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "ALLIED INTELLIGENCE", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_textbox(slide, Inches(1.0), Inches(1.6), Inches(11), Inches(1.0),
                 "Objective-See", 48, TEXT_WHITE, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_multiline(slide, Inches(1.2), Inches(2.8), Inches(10.5), Inches(4.0), [
        ("Free, open-source macOS security tools", TEXT_LIGHT, False, 24),
        ("by Patrick Wardle", TEXT_LIGHT, False, 24),
        ('', TEXT_DIM, False, 10),
        ("BlockBlock  ·  LuLu  ·  RansomWhere", ACCENT_AMBER, True, 22),
        ("OverSight  ·  ReiKey  ·  KnockKnock", ACCENT_AMBER, True, 22),
        ('', TEXT_DIM, False, 10),
        ("These form the backbone of our monitoring layer.", TEXT_LIGHT, False, 22),
        ("Think of them as our network of field agents,", TEXT_LIGHT, False, 22),
        ("each watching a different angle.", TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 10),
        ("objective-see.org", ACCENT_GREEN, True, 22),
    ], font_name=FONT_NAME, alignment=PP_ALIGN.CENTER)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Give a shout-out to the Objective-See suite of free, open-source '
                       'macOS security tools by Patrick Wardle.')


def slide_workflow(prs):
    """
    Slide [REMOVED] — The workflow steps (no longer in build).
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "OPERATION PLAYBOOK", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    steps = [
        ("01", "Profile \u2014 collect system state "
         "& tool details", TEXT_LIGHT),
        ("02", "Scan \u2014 run the asset through "
         "intelligence agencies", TEXT_LIGHT),
        ("03", "Monitor \u2014 start real-time "
         "surveillance", TEXT_LIGHT),
        ("04", "Install \u2014 deploy the asset "
         "in isolation", TEXT_LIGHT),
        ("05", "Analyse \u2014 inspect the asset and "
         "monitor behaviour", TEXT_LIGHT),
        ("06", "Uninstall \u2014 remove the asset "
         "& verify clean extraction", TEXT_LIGHT),
        ("07", "Stop Monitoring \u2014 stand down "
         "real-time surveillance", TEXT_LIGHT),
        ("08", "Report \u2014 compile the full "
         "dossier", TEXT_LIGHT),
        ("09", "Decide \u2014 clear or reject",
         TEXT_LIGHT),
    ]

    y = Inches(1.5)
    for num, desc, clr in steps:
        _add_textbox(slide, Inches(0.8), y, Inches(1.0), Inches(0.4),
                     f"[{num}]", 20, ACCENT_RED, True,
                     font_name=FONT_NAME)
        _add_textbox(slide, Inches(2.0), y, Inches(10.5), Inches(0.4),
                     desc, 20, clr, font_name=FONT_NAME)
        y += Inches(0.65)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Give a high-level overview of the workflow steps involved in the '
                       'software verification process.')


def _add_tool_screenshot(slide, img_filename, left, top, width, height):
    """
    Embed a tool screenshot if the file exists, otherwise add placeholder text.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    img_path = os.path.join(script_dir, img_filename)
    if os.path.exists(img_path):
        slide.shapes.add_picture(img_path, left, top, width, height)
    else:
        _add_textbox(slide, left, top, width, Inches(0.5),
                     f"[ {img_filename} ]", 14, TEXT_DIM,
                     alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)


def slide_tool_virustotal(prs):
    """
    Slide — VirusTotal deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3),
                 Inches(12), Inches(0.8),
                 "VIRUSTOTAL", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3),
                   Inches(5.5), Inches(4.0), [
        ("70+ antivirus engines in one scan",
         TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("We use VirusTotal for two things:",
         TEXT_LIGHT, False, 16),
        ('', TEXT_DIM, False, 4),
        ("  1.  Upload installer media",
         TEXT_LIGHT, False, 16),
        ("      (DMG, PKG, ZIP \u2014 up to 600MB)",
         TEXT_DIM, False, 14),
        ('', TEXT_DIM, False, 2),
        ("  2.  Submit captured URLs/IPs",
         TEXT_LIGHT, False, 16),
        ("      (from LuLu network intercepts)",
         TEXT_DIM, False, 14),
        ('', TEXT_DIM, False, 6),
        ("API KEY REQUIRED", ACCENT_AMBER, True, 16),
        ("  \u2022  Free public tier works fine",
         TEXT_LIGHT, False, 14),
        ("  \u2022  600MB upload limit",
         TEXT_LIGHT, False, 14),
        ("  \u2022  Fine for business workflows as",
         TEXT_LIGHT, False, 14),
        ("     long as you upload new samples",
         TEXT_LIGHT, False, 14),
        ('', TEXT_DIM, False, 6),
        ("virustotal.com",
         ACCENT_GREEN, True, 16),
    ], font_name=FONT_NAME, line_spacing=1.1)

    # Right side — screenshot (3596x1840, ~1.95:1)
    _add_tool_screenshot(slide, 'screenshot_virustotal.png',
                         Inches(6.8), Inches(2.0),
                         Inches(6.0), Inches(3.07))

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.3),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('OSX.Dummy (2018) \u2014 0/60 AV engines; '
         '3CX supply chain (2023) \u2014 0 detections',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x32.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 We use it in two ways: '
        'first, we upload the installer media itself '
        'and scan.  We then submit any URLs or IP '
        'addresses captured by LuLu during install or '
        'after launching the application.\n\n'
        'You\u2019ll need an API key, the free public tier '
        'works fine for this, there is a 600MB upload '
        'limit, which covers most installer media. '
        'It\u2019s perfectly fine for business workflows '
        'as long as you\u2019re uploading new samples '
        '\u2013 VirusTotal shares submissions with the '
        'security community, so just be aware of that '
        'if you\u2019re testing internal software.\n\n'
        'Real-world: In 2018, OSX.Dummy targeted the '
        'crypto community and was completely undetected '
        '\u2013 zero out of 60 AV engines flagged it on '
        'VirusTotal. Similarly, in 2023 the trojanized '
        '3CX supply chain attack shipped a malicious '
        'libffmpeg.dylib that was notarized by Apple and '
        'undetected by every AV engine on VirusTotal when '
        'first uploaded. These cases show why we can\u2019t '
        'rely solely on VT.')


def slide_tool_threatlabs(prs):
    """
    Slide — Jamf Threat Labs binary scanning.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3),
                 Inches(12), Inches(0.8),
                 "JAMF THREAT LABS", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3),
                   Inches(6.35), Inches(2.98), [
        ("Mach-O binary deep-scan",
         TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Scans executable binaries",
         TEXT_LIGHT, False, 16),
        ("  \u2022  Validates Mach-O header signatures",
         TEXT_LIGHT, False, 16),
        ("  \u2022  YARA rule matching",
         TEXT_LIGHT, False, 16),
        ("  \u2022  Threat level classification",
         TEXT_LIGHT, False, 16),
        ('', TEXT_DIM, False, 6),
        ("API KEY REQUIRED - 30 day renewal",
         ACCENT_AMBER, True, 16),
        ("  \u2022  Currently in beta for Jamf customers",
         TEXT_LIGHT, False, 14),
        ("  \u2022  Speak to Ben or Paul for an invite"
         " to the beta!",
         ACCENT_GREEN, True, 14),
        ('', TEXT_DIM, False, 6),
    ], font_name=FONT_NAME, line_spacing=1.1)

    # Right side — screenshot (1036x1518, portrait)
    _add_tool_screenshot(
        slide, 'screenshot_threatlabs_welcome.png',
        Inches(7.8), Inches(1.3),
        Inches(3.4), Inches(5.0))

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 Jamf Threat Labs provides dedicated '
        'Mach-O binary scanning. Where VirusTotal scans '
        'the installer media as a whole, Threat Labs goes '
        'deeper \u2013 it scans executable binaries, '
        'validates Mach-O headers, runs YARA '
        'rules, and classifies threat levels.\n\n'
        'It needs an API key that renews every 30 days '
        'and is currently in beta for Jamf customers. '
        'If you\u2019d like an invite to the beta, come '
        'and speak to Ben or myself after the demo.')


def slide_tool_threatlabs_dashboard(prs):
    """
    Slide — Jamf Threat Labs dashboard screenshot.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3),
                 Inches(12), Inches(0.8),
                 "JAMF THREAT LABS", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    # Dashboard screenshot (2448x1854, ~1.32:1)
    _add_tool_screenshot(
        slide, 'screenshot_threatlabs_dashboard.png',
        Inches(2.9), Inches(1.4),
        Inches(7.5), Inches(5.7))

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 This is the Threat Labs dashboard. '
        'You can see the upload area for Mach-O binaries, '
        'recent submissions with their status, and the '
        'quick stats showing total submissions and threats '
        'detected. The submissions table shows the full '
        'history with file names, status, and the ability '
        'to view detailed results for each scan.')


def slide_tool_threatlabs_results(prs):
    """
    Slide — Jamf Threat Labs analysis results (3 views).
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3),
                 Inches(12), Inches(0.8),
                 "THREAT LABS: VIEW RESULTS", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    # 1. Standard results (no threats, hashes, detection)
    # 1816×1650 → 4.1 × 3.73
    _add_tool_screenshot(
        slide, 'screenshot_threatlabs_results_std.png',
        Inches(0.3), Inches(1.3),
        Inches(4.1), Inches(3.73))

    # 2. AI Analysis / classification
    # 1702×1246 → 4.1 × 3.00
    _add_tool_screenshot(
        slide, 'screenshot_threatlabs_results_ai.png',
        Inches(4.6), Inches(1.3),
        Inches(4.1), Inches(3.0))

    # 3. Behavioral Analysis / reasoning
    # 1812×1782 → 4.1 × 4.03
    _add_tool_screenshot(
        slide, 'screenshot_threatlabs_results_beh.png',
        Inches(8.9), Inches(1.3),
        Inches(4.1), Inches(4.03))

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 Three examples of the Threat Labs results '
        'page. On the left is the standard result \u2013 '
        'threat assessment, file hashes, analysis details, '
        'and the detection methods used: Team ID analysis, '
        'SHA1 hash lookup, and YARA rules.\n\n'
        'In the middle is the AI Analysis for a flagged '
        'binary \u2013 security classification, threat level, '
        'and file classification identifying the type of '
        'tool, vendor, architecture, and code signing '
        'status.\n\n'
        'On the right is the Behavioral Analysis and '
        'reasoning. It examines the binary\u2019s strings, '
        'frameworks, and capabilities to determine what '
        'the application actually does. In this example '
        'it identified a network monitoring tool with '
        'socket operations and an unknown Team ID \u2013 '
        'flagging it as medium threat requiring further '
        'verification.')


def slide_tool_reikey(prs):
    """
    Slide — ReiKey deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "REIKEY", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3),
                   Inches(5.5), Inches(3.5), [
        ("Keyboard event tap monitor", TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Detects CoreGraphics event taps",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Scans for existing keyboard taps",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Alerts on new tap installation",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Passive listener vs active filter",
         TEXT_LIGHT, False, 15),
        ('', TEXT_DIM, False, 4),
        ("objective-see.org/products/reikey.html",
         ACCENT_AMBER, True, 16),
    ], font_name=FONT_NAME, line_spacing=1.15)

    # Right side — screenshot
    _add_tool_screenshot(slide, 'alert_reikey.png',
                         Inches(6.8), Inches(1.3),
                         Inches(6.0), Inches(3.5))

    # Command line example at bottom
    _add_textbox(slide, Inches(0.8), Inches(5.15),
                 Inches(11.5), Inches(0.4),
                 "COMMAND LINE:", 18, ACCENT_RED, True,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.55),
                   Inches(11.5), Inches(0.7), [
        ('/Applications/ReiKey.app/Contents/'
         'MacOS/ReiKey -scan -pretty -skipApple',
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ('Output: JSON \u2014 active keyboard event '
         'taps with process & target info',
         TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.4),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('OSX.FruitFly \u2014 keylogger with event '
         'taps undetected for 13+ years',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x36.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 ReiKey scans for and monitors '
        'CoreGraphics keyboard event taps \u2013 the most '
        'common technique used by macOS keyloggers. It can '
        'scan for existing taps and alert in real time when '
        'a new one is installed.\n\n'
        'During testing we run a scan before and after '
        'installation. Any new keyboard event tap installed '
        'by the title under test is flagged \u2013 legitimate '
        'apps rarely need to intercept keystrokes globally.\n\n'
        'The tool distinguishes between passive listeners '
        'and active filters, which helps gauge the severity '
        'of the finding.\n\n'
        'Real-world: OSX.FruitFly was written over a decade '
        'ago but only discovered in 2017. It installed '
        'keyboard event taps to log keystrokes and used '
        'synthetic mouse and keyboard events to dismiss '
        'security prompts \u2013 even dumping the user\u2019s '
        'keychain. ReiKey would have detected the event '
        'tap installation immediately.')


def slide_tool_dhs(prs):
    """
    Slide — Dylib Hijack Scanner deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "DHS",
                 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3),
                   Inches(5.5), Inches(3.5), [
        ("Dynamic library hijack detector",
         TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Scans for vulnerable applications",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Detects hijacked dylibs",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Weak import hijack detection",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Full filesystem scan option",
         TEXT_LIGHT, False, 15),
        ('', TEXT_DIM, False, 4),
        ("objective-see.org/products/dhs.html",
         ACCENT_AMBER, True, 16),
    ], font_name=FONT_NAME, line_spacing=1.15)

    # Right side — screenshot
    _add_tool_screenshot(slide, 'alert_dhs.png',
                         Inches(6.8), Inches(1.3),
                         Inches(6.0), Inches(3.5))

    # Note at bottom
    _add_textbox(slide, Inches(0.8), Inches(5.15),
                 Inches(11.5), Inches(0.4),
                 "WHAT WE CHECK:", 18, ACCENT_RED, True,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.55),
                   Inches(11.5), Inches(0.7), [
        ('Post-install scan \u2192 does the title '
         'introduce any hijackable or hijacked dylibs?',
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ('Findings saved as JSON via '
         "'save results' preference",
         TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.4),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('Zoom (2020) \u2014 dylib proxy hijack '
         'gave mic & camera access without prompts',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x56.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 DHS \u2013 Dylib Hijack Scanner \u2013 '
        'checks for applications vulnerable to dynamic '
        'library hijacking and detects any that have '
        'already been hijacked.\n\n'
        'Dylib hijacking is a technique where an attacker '
        'plants a malicious dynamic library in a location '
        'that the OS will load before the legitimate one. '
        'This can give persistence and code execution in '
        'the context of a trusted application.\n\n'
        'After installing a title, we run DHS to check '
        'whether the new application introduces any '
        'hijackable paths or, worse, ships with already-'
        'hijacked libraries. DHS favours false positives '
        'over false negatives, so we cross-reference '
        'findings against the known false-positive list.\n\n'
        'Real-world: In 2020, Patrick Wardle demonstrated '
        'that Zoom\u2019s macOS client had a '
        'disable-library-validation entitlement, allowing '
        'any library to be loaded into its process space. '
        'By proxying a legitimate SSL library, an attacker '
        'could inherit Zoom\u2019s mic and camera access '
        '\u2013 completely invisible to the user. DHS '
        'would flag the hijackable dylib paths. Many other '
        'apps including Tresorit and MS Office had similar '
        'vulnerabilities.')


def slide_tool_xprotect(prs):
    """
    Slide — XProtect deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "XPROTECT", 44, ACCENT_RED, True,
                 font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3), Inches(11.5), Inches(3.9), [
        ("Apple's built-in antivirus technology", TEXT_WHITE, True, 24),
        ('', TEXT_DIM, False, 6),
        ("  •  YARA signature-based detection", TEXT_LIGHT, False, 20),
        ("  •  Blocks execution of known malware", TEXT_LIGHT, False, 20),
        ("  •  Remediates infections automatically", TEXT_LIGHT, False, 20),
        ("  •  Scans on first launch & file changes", TEXT_LIGHT, False, 20),
        ("  •  Signatures updated independently of OS", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 6),
        ("  🔗 support.apple.com/en-gb/guide/security/sec469d47bd8/web",
         TEXT_DIM, False, 14),
    ], font_name=FONT_NAME, line_spacing=1.4)

    # Unified log example at bottom
    _add_textbox(slide, Inches(0.8), Inches(5.15),
                 Inches(11.5), Inches(0.4),
                 "UNIFIED LOG:", 18, ACCENT_RED, True,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.55),
                   Inches(11.5), Inches(0.78), [
        ('log stream --predicate "subsystem == '
         "'com.apple.xprotect'\"",
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ('Events: malware detection, quarantine actions, '
         'signature updates', TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.4),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('Bonzai (2025) \u2014 DPRK stealer '
         'detected via XProtect v5304 YARA rules',
         ACCENT_AMBER, True, 13),
        ('eclecticlight.co/2025/07/11/'
         'what-happened-to-xprotect-this-week',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 XProtect is Apple\u2019s built-in antivirus, '
        'using YARA signatures to detect known malware. It works '
        'in three layers: preventing launch via the App Store and '
        'Gatekeeper, blocking known malware from running, and '
        'remediating infections that slip through.\n\n'
        'Signatures are updated automatically and independently '
        'of system updates. XProtect scans apps on first launch '
        'and whenever they change on disc.\n\n'
        'We monitor XProtect events during testing via the unified '
        'log, watching for any malware detections or quarantine '
        'actions triggered by the title under test.\n\n'
        'Real-world: In July 2025, Apple pushed XProtect v5304 '
        'with substantial new YARA rules for a malware family '
        'code-named Bonzai \u2013 five variants including '
        'Bonanza, Barricade, Blaster, Bonder and Banana. '
        'Security researchers linked these to DPRK\u2019s '
        'BlueNoroff group targeting crypto and Web3 platforms. '
        'The malware was a stealer written in Go, targeting '
        'browser extensions for Chrome, Brave, Edge and Firefox. '
        'Apple also used MRT to forcibly remove Zoom\u2019s '
        'vulnerable web server component from Macs worldwide '
        'in 2019 \u2013 the only time they\u2019ve taken that '
        'action.\n\n'
        'Reference: https://support.apple.com/en-gb/guide/security/'
        'sec469d47bd8/web')


def slide_tool_lulu(prs):
    """
    Slide — LuLu deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "LULU", 44, ACCENT_RED, True,
                 font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3), Inches(5.5), Inches(3.5), [
        ("macOS firewall", TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Monitors all outbound connections", TEXT_LIGHT, False, 15),
        ("  \u2022  Intercepts URLs/IPs for VT analysis", TEXT_LIGHT, False, 15),
        ('', TEXT_DIM, False, 4),
        ("objective-see.org/products/lulu.html", ACCENT_AMBER, True, 16),
    ], font_name=FONT_NAME, line_spacing=1.3)

    # Right side — screenshot
    _add_tool_screenshot(slide, 'alert_lulu.png',
                         Inches(6.8), Inches(1.3), Inches(6.0), Inches(3.5))

    # Unified log example at bottom
    _add_textbox(slide, Inches(0.8), Inches(5.3), Inches(11.5), Inches(0.4),
                 "UNIFIED LOG:", 18, ACCENT_RED, True, font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.8), Inches(11.5), Inches(0.7), [
        ('log stream --level debug '
         '--predicate "subsystem='
         "'com.objective-see.lulu'\"",
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ('Events: (user) response:, presenting alert, '
         'creating rule', TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.6),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('OSX.Dummy (2018) \u2014 LuLu caught '
         'reverse shell to 185.243.115.230:1337',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x32.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 LuLu is a firewall for '
        'macOS. It monitors all outbound network '
        'connections and alerts you when an application tries to '
        'connect to a remote server.\n\n'
        'During testing, we stream LuLu\u2019s events via '
        'the unified log.\n\n'
        'Captured connections are then submitted to VirusTotal '
        'for analysis. \u2013 pretty common to see connections '
        'to CDN\u2019s and update feeds.\n\n'
        'Real-world: In 2018, OSX.Dummy tricked crypto '
        'community users into running a malicious binary. '
        'The malware set up a persistent reverse shell to '
        '185.243.115.230 on port 1337, giving the attacker '
        'root access. LuLu detected this outbound connection '
        'immediately \u2013 even though every AV engine on '
        'VirusTotal missed the malware entirely.')


def slide_tool_blockblock(prs):
    """
    Slide — BlockBlock deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "BLOCKBLOCK", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.41), Inches(1.3), Inches(5.89), Inches(2.08), [
        ("Persistence mechanism monitor", TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Monitors persistence locations", TEXT_LIGHT, False, 15),
        ("  \u2022  Detects login items & BTM changes", TEXT_LIGHT, False, 15),
        ("  \u2022  ClickFix paste protection (v2.3.0+)", TEXT_LIGHT, False, 15),
        ("  \u2022  Real-time allow/block decisions", TEXT_LIGHT, False, 15),
        ('', TEXT_DIM, False, 4),
        ("objectivesee.org/products/blockblock.html", ACCENT_AMBER, True, 16),
    ], font_name=FONT_NAME, line_spacing=1.15)

    # Right side — screenshot
    _add_tool_screenshot(slide, 'alert_blockblock.png',
                         Inches(6.8), Inches(1.3), Inches(6.0), Inches(3.5))

    # Unified log example at bottom
    _add_textbox(slide, Inches(0.8), Inches(5.3), Inches(11.5), Inches(0.4),
                 "UNIFIED LOG:", 18, ACCENT_RED, True, font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.8), Inches(11.5), Inches(0.78), [
        ('log stream --predicate "subsystem == '
         "'com.objective-see.blockblock'\"",
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ("Events: user says 'allow'/'block', "
         "installed a launch daemon/agent",
         TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.6),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('OSX.Dummy (2018) \u2014 caught '
         'com.startup.plist LaunchDaemon persistence',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x32.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 BlockBlock monitors persistence locations on '
        'macOS. Whenever something tries to install a new '
        'LaunchAgent, LaunchDaemon, login item, or other '
        'persistence mechanism, BlockBlock raises an alert.\n\n'
        'We capture these events from the unified log during '
        'testing. This tells us exactly what persistence '
        'mechanisms the title installs \u2013 which also feeds '
        'directly into the configuration profiles we generate.\n\n'
        'Real-world: In 2018, OSX.Dummy installed a malicious '
        'LaunchDaemon at /Library/LaunchDaemons/com.startup.plist '
        'that persisted a reverse shell script. BlockBlock '
        'detected and alerted on this persistence attempt '
        'immediately. In 2026, BlockBlock v2.3.0 added paste '
        'protection against ClickFix attacks \u2013 where '
        'attackers trick users into pasting malicious commands '
        'into Terminal. North Korean actors used this technique '
        'in fake video calls, and LLM-generated instructions '
        'were found propagating ClickFix payloads via Google '
        'Sponsored results.')


def slide_tool_knockknock(prs):
    """
    Slide — KnockKnock deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "KNOCKKNOCK", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.63), Inches(1.3), Inches(5.67), Inches(2.25), [
        ("Persistence mechanism scanner", TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Scans for persistent software", TEXT_LIGHT, False, 16),
        ("  \u2022  LaunchAgents/Daemons, login items", TEXT_LIGHT, False, 16),
        ("  \u2022  Browser & kernel extensions", TEXT_LIGHT, False, 16),
        ("  \u2022  Shell config (.zshrc, .bashrc)", TEXT_LIGHT, False, 16),
        ("  \u2022  VirusTotal v3 API integration", TEXT_LIGHT, False, 16),
        ("  \u2022  BTM enumeration (v4.0.3+)", TEXT_LIGHT, False, 16),
    ], font_name=FONT_NAME, line_spacing=1.1)

    # Right side — screenshot
    _add_tool_screenshot(slide, 'alert_knockknock.png',
                         Inches(6.8), Inches(1.3), Inches(6.0), Inches(3.0))

    # Before/after note
    _add_textbox(slide, Inches(0.8), Inches(4.5), Inches(11.5), Inches(0.4),
                 "Before/after comparison: baseline scan "
                 "\u2192 post-install delta", 17,
                 ACCENT_AMBER, True, font_name=FONT_NAME)

    # Command example at bottom
    _add_textbox(slide, Inches(0.8), Inches(5.3), Inches(11.5), Inches(0.4),
                 "COMMAND LINE:", 18, ACCENT_RED, True,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.8), Inches(11.5), Inches(0.7), [
        ('/Applications/KnockKnock.app/Contents/'
         'MacOS/KnockKnock '
         '-whosthere -verbose -pretty',
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ('Output: JSON \u2014 persistence items across '
         '20+ categories', TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.6),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('OSX.Dummy \u2014 found unsigned persistence; '
         'Zoom \u2014 detected proxy dylib',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x32.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 KnockKnock scans for persistently installed '
        'software. Unlike the streaming tools, it\u2019s a '
        'point-in-time scanner \u2013 we run it before and after '
        'installation and compare the results. \n\n'
        'The delta tells us exactly what persistence mechanisms '
        'the title added: LaunchAgents, LaunchDaemons, login '
        'items, browser extensions, shell config changes, and '
        'more. Version 4.0.3 added enhanced BTM enumeration, and '
        'the VirusTotal v3 API integration lets us cross-reference '
        'any new items with 70+ antivirus engines.\n\n'
        'Real-world: Running KnockKnock as root on a system '
        'infected with OSX.Dummy revealed the unsigned '
        'com.startup.plist LaunchDaemon executing a script from '
        '/var/root/ \u2013 the malware\u2019s persistence '
        'mechanism laid bare. In the 2020 Zoom vulnerability, '
        'KnockKnock detected the proxy library injection in '
        'Zoom\u2019s Frameworks directory \u2013 a dylib that '
        'wasn\u2019t part of the original application bundle.')


def slide_tool_ransomwhere(prs):
    """
    Slide — RansomWhere deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "RANSOMWHERE?", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.18), Inches(1.3), Inches(6.98), Inches(2.36), [
        ("Ransomware detection via file-system", TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Monitors for encrypted file creation", TEXT_LIGHT, False, 15),
        ("  \u2022  Detects suspicious encryption patterns", TEXT_LIGHT, False, 15),
        ("  \u2022  Suspends offending processes", TEXT_LIGHT, False, 15),
        ("  \u2022  User allow/terminate decision", TEXT_LIGHT, False, 15),
        ("  \u2022  v2.0+ Apple Endpoint Security API", TEXT_LIGHT, False, 15),
        ('', TEXT_DIM, False, 4),
        ("objective-see.org/products/ransomwhere.html", ACCENT_AMBER, True, 16),
    ], font_name=FONT_NAME, line_spacing=1.15)

    # Right side — screenshot
    _add_tool_screenshot(slide, 'alert_ransomwhere.png',
                         Inches(7.16), Inches(1.3),
                         Inches(6.0), Inches(3.5))

    # Unified log example at bottom
    _add_textbox(slide, Inches(0.8), Inches(5.3),
                 Inches(11.5), Inches(0.4),
                 "UNIFIED LOG:", 18, ACCENT_RED, True,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.8),
                   Inches(11.5), Inches(0.7), [
        ('log stream --level debug '
         '--predicate "subsystem='
         "'com.objective-see.ransomwhere'\"",
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ("Events: file is encrypted, suspended: "
         "<process>, user says 'allow'",
         TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.6),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('Turtle ransomware (2023) \u2014 '
         'generically thwarted with zero prior knowledge',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x76.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 RansomWhere monitors the file system for the '
        'rapid creation of encrypted files \u2013 a hallmark of '
        'ransomware. When it detects suspicious encryption activity, '
        'it suspends the offending process and alerts the user.\n\n'
        'Version 2.0 moved to Apple\u2019s Endpoint Security '
        'framework for better detection. We stream its events '
        'during testing to ensure the title under test isn\u2019t '
        'doing anything that looks like ransomware behavior.\n\n'
        'Note - Not uncommon for apps to encrypt files, for '
        'example Chromium based apps tend to encrypt some files '
        'in user space Application Support. So you really want '
        'to pay attention to where the files are being encrypted, '
        'and how many!\n\n'
        'Real-world: In 2023, a cross-platform ransomware called '
        'Turtle appeared, written in Go with builds for macOS, '
        'Windows and Linux. RansomWhere generically detected and '
        'thwarted it with absolutely no prior knowledge of the '
        'malware \u2013 it simply spotted the rapid creation of '
        'encrypted files by an untrusted process. Patrick Wardle '
        'also recovered the hardcoded AES key '
        '"wugui123wugui123" (wugui means turtle in Chinese) '
        'and published a decryptor. Sponsored by Jamf, '
        'no less!')


def slide_tool_oversight(prs):
    """
    Slide — OverSight deep-dive.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "OVERSIGHT", 44, ACCENT_RED, True,
                 font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3),
                   Inches(5.87), Inches(1.52), [
        ("Camera & microphone monitor",
         TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Monitors internal mic activation",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Detects webcam access by processes",
         TEXT_LIGHT, False, 15),
        ('', TEXT_DIM, False, 4),
        ("objective-see.org/products/oversight.html",
         ACCENT_AMBER, True, 16),
    ], font_name=FONT_NAME, line_spacing=1.15)

    # Right side — screenshot (OverSight is a small notification,
    # so size proportionally and centre vertically)
    _add_tool_screenshot(slide, 'alert_oversight.png',
                         Inches(7.0), Inches(1.3),
                         Inches(5.5), Inches(1.56))

    # Unified log example at bottom
    _add_textbox(slide, Inches(0.8), Inches(4.97),
                 Inches(11.5), Inches(0.4),
                 "UNIFIED LOG:", 18, ACCENT_RED, True,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(5.5),
                   Inches(11.5), Inches(0.7), [
        ('log stream --level debug '
         '--predicate "subsystem='
         "'com.objective-see.oversight'\"",
         ACCENT_GREEN, False, 14),
        ('', TEXT_DIM, False, 4),
        ('Events: camera access detected, '
         'microphone access detected',
         TEXT_DIM, False, 14),
    ], font_name=FONT_NAME)

    # Real-world example
    _add_multiline(slide, Inches(0.8), Inches(6.4),
                   Inches(11.5), Inches(0.9), [
        ("REAL WORLD:", ACCENT_RED, True, 14),
        ('Zoom (2020) \u2014 OverSight caught invisible '
         'background mic & camera hijacking',
         ACCENT_AMBER, True, 13),
        ('objective-see.org/blog/blog_0x56.html',
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 OverSight monitors your Mac\u2019s camera and '
        'microphone. If any process activates the mic or accesses '
        'the webcam, OverSight raises an alert and identifies the '
        'responsible process.\n\n'
        'During testing, we stream these events to catch any title '
        'that silently accesses audio or video hardware. \n\n'
        'Real-world: In 2020, Patrick Wardle demonstrated that '
        'malicious code injected into Zoom\u2019s process could '
        'inherit its mic and camera permissions \u2013 recording '
        'audio and video with zero user prompts. Zoom could even '
        'be launched hidden via /usr/bin/open -j. OverSight would '
        'alert the user any time the mic or camera activated, even '
        'from an invisible Zoom session. Earlier, in 2016, '
        'OverSight exposed Shazam keeping the microphone active '
        'even when the user toggled it off \u2013 proving the '
        'tool catches both malicious and misbehaving software.')


def slide_tool_config_profiles(prs):
    """
    Slide — Configuration Profiles: suspicious access & what we look for.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "CONFIG PROFILES", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.3), Inches(5.5), Inches(3.0), [
        ("Auto-generated MDM profiles", TEXT_WHITE, True, 20),
        ("based on observed behaviour", TEXT_WHITE, True, 20),
        ('', TEXT_DIM, False, 4),
        ("  \u2713  PPPC (Privacy Preferences)", ACCENT_GREEN, False, 15),
        ("  \u2713  Notifications allowlisting", ACCENT_GREEN, False, 15),
        ("  \u2713  System Extensions", ACCENT_GREEN, False, 15),
        ("  \u2713  Managed Login Items", ACCENT_GREEN, False, 15),
        ("  \u2713  Screen Recording permissions", ACCENT_GREEN, False, 15),
        ("  \u2713  Content Filters", ACCENT_GREEN, False, 15),
        ("  \u2713  Kernel Extensions (legacy)", ACCENT_GREEN, False, 15),
    ], font_name=FONT_NAME, line_spacing=1.15)

    _add_multiline(slide, Inches(6.8), Inches(1.3), Inches(6.0), Inches(3.0), [
        ("WHY DOES THIS APP NEED THAT?", ACCENT_AMBER, True, 18),
        ('', TEXT_DIM, False, 4),
        ("\u2713  Zoom \u2192 Camera, Mic", ACCENT_GREEN, False, 15),
        ("     Makes sense for video calls", TEXT_DIM, False, 13),
        ('', TEXT_DIM, False, 2),
        ("\u26a0  Text editor \u2192 Camera", ACCENT_AMBER, False, 15),
        ("     Why does Notepad need a camera?", TEXT_DIM, False, 13),
        ('', TEXT_DIM, False, 2),
        ("\u26a0  Calculator \u2192 Full Disk Access", ACCENT_AMBER, False, 15),
        ("     Highly suspicious", TEXT_DIM, False, 13),
        ('', TEXT_DIM, False, 2),
        ("\u26a0  PDF viewer \u2192 Accessibility", ACCENT_AMBER, False, 15),
        ("     Unusual unless it has automation", TEXT_DIM, False, 13),
    ], font_name=FONT_NAME, line_spacing=1.15)

    # Bottom section — NS Usage Description keys
    _add_textbox(slide, Inches(0.8), Inches(4.45),
                 Inches(11.5), Inches(0.4),
                 "NS USAGE DESCRIPTIONS WE CHECK (Info.plist):",
                 18, ACCENT_RED, True, font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(4.85), Inches(11.5), Inches(2.4), [
        ("NSCameraUsageDescription             "
         "NSMicrophoneUsageDescription",
         ACCENT_GREEN, False, 12),
        ("NSAppleEventsUsageDescription        "
         "NSScreenCaptureUsageDescription",
         ACCENT_GREEN, False, 12),
        ("NSAccessibilityUsageDescription      "
         "NSLocationUsageDescription",
         ACCENT_GREEN, False, 12),
        ("NSContactsUsageDescription           "
         "NSCalendarsUsageDescription",
         ACCENT_GREEN, False, 12),
        ("NSPhotoLibraryUsageDescription       "
         "NSRemindersUsageDescription",
         ACCENT_GREEN, False, 12),
        ('', TEXT_DIM, False, 4),
        ("These declare what the app says it needs "
         "\u2014 we verify against actual entitlements.",
         TEXT_DIM, False, 12),
        ('', TEXT_DIM, False, 4),
        ("macOS uses just-in-time enablement \u2014 apps may not "
         "request access until they actually need it.",
         ACCENT_AMBER, True, 12),
        ("Check entitlements up front to see what an app is "
         "capable of asking for.",
         ACCENT_AMBER, False, 12),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 One of the most useful outputs is the automatic '
        'generation of configuration profiles. But the key insight '
        'is context \u2013 does the access request make sense?\n\n'
        'Zoom asking for camera and mic? Pretty reasonable, right? A '
        'text editor asking for camera access? That\u2019s a red '
        'flag. A calculator wanting Full Disk Access? That\u2019s '
        'suspicious.\n\n'
        'Crucially, we check these because of just-in-time '
        'enablement. macOS uses a just-in-time model for '
        'permissions \u2013 an app might not request access to '
        'the camera, microphone, or file system until it '
        'actually needs to perform that action. So you can\u2019t '
        'just install an app and wait for prompts \u2013 you '
        'need to check the entitlements and Info.plist '
        'declarations up front to know what it\u2019s capable '
        'of asking for, even if it hasn\u2019t asked yet.\n\n'
        'We check the NS Usage Description keys in the Info.plist '
        'to see what the app declares it needs, then we verify '
        'those claims against the actual code signature '
        'entitlements. Any mismatch is flagged.')


def slide_tool_config_profiles_entitlements(prs):
    """
    Slide — On-disk discovery: sfltool dumpbtm and beyond entitlements.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3),
                 Inches(12), Inches(0.8),
                 "ON-DISK DISCOVERY", 44,
                 ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    # Left — why entitlements aren't enough
    _add_multiline(slide, Inches(0.8), Inches(1.3),
                   Inches(5.5), Inches(2.0), [
        ("Why entitlements aren't enough",
         TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Not all developers declare them",
         TEXT_LIGHT, False, 15),
        ("  \u2022  NS Usage keys often missing",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Some apps install helpers/agents",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Need to see what's actually on disk",
         TEXT_LIGHT, False, 15),
    ], font_name=FONT_NAME, line_spacing=1.2)

    # Right — what we inspect
    _add_multiline(slide, Inches(6.8), Inches(1.3),
                   Inches(6.0), Inches(2.0), [
        ("What we inspect post-install",
         TEXT_WHITE, True, 22),
        ('', TEXT_DIM, False, 4),
        ("  \u2022  Background Task Management (BTM)",
         TEXT_LIGHT, False, 15),
        ("  \u2022  LaunchAgents & LaunchDaemons",
         TEXT_LIGHT, False, 15),
        ("  \u2022  Login items & helper tools",
         TEXT_LIGHT, False, 15),
        ("  \u2022  System & network extensions",
         TEXT_LIGHT, False, 15),
    ], font_name=FONT_NAME, line_spacing=1.2)

    # Commands section
    _add_textbox(slide, Inches(0.8), Inches(3.6),
                 Inches(11.5), Inches(0.4),
                 "KEY COMMANDS:", 18, ACCENT_RED, True,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(4.1),
                   Inches(11.5), Inches(3.2), [
        ("sfltool dumpbtm",
         ACCENT_GREEN, True, 15),
        ("  \u2192 Dumps Background Task Management "
         "database \u2014 login items, agents, daemons",
         TEXT_DIM, False, 13),
        ('', TEXT_DIM, False, 4),
        ("systemextensionsctl list",
         ACCENT_GREEN, True, 15),
        ("  \u2192 Lists all installed system extensions "
         "(network filters, endpoint security)",
         TEXT_DIM, False, 13),
        ('', TEXT_DIM, False, 6),
        ("We combine these with entitlement and "
         "persistence data to auto-generate "
         "PPPC, login item, and extension profiles.",
         ACCENT_AMBER, True, 13),
    ], font_name=FONT_NAME, line_spacing=1.0)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = (
        'PC \u2013 So, we can\u2019t relay solely on '
        'entitlements and NS Usage Description keys. Not '
        'all developers declare them properly, and some '
        'don\u2019t declare them at all. An app might '
        'install helper tools, background agents, or login '
        'items that don\u2019t show up in the main '
        'app\u2019s entitlements.\n\n'
        'So we go beyond entitlements and look at '
        'what\u2019s actually on disk after installation. '
        'The key tool here is sfltool dumpbtm, which dumps '
        'the Background Task Management database. This '
        'tells us every login item, LaunchAgent, and '
        'LaunchDaemon that the system knows about \u2013 '
        'regardless of whether the developer declared '
        'anything in their entitlement \u2013 there is '
        'definetly overlap here with BlockBlock, and '
        'KnockKnock, but we want to sure we catch as '
        'much possible. \n\n'
        'We also enumerate system extensions with '
        'systemextensionsctl. By combining these on-disk '
        'sources with the '
        'entitlement and persistence data from our other '
        'tools, we can auto-generate accurate PPPC, login '
        'item, and extension profiles that reflect what '
        'the app actually does, not just what the '
        'developer says it does.')


def slide_phase_preinstall(prs):
    """
    Slide — Pre-install state capture.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "PHASE 1: RECONNAISSANCE", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_textbox(slide, Inches(0.8), Inches(1.4), Inches(11), Inches(0.8),
                 "Before the asset lands, photograph everything.", 24, TEXT_WHITE,
                 font_name=FONT_NAME)

    _add_multiline(slide, Inches(0.8), Inches(2.4), Inches(11.5), Inches(4.5), [
        ("$ sfltool dumpbtm", ACCENT_GREEN, True, 22),
        ("  → Background Task Management snapshot", TEXT_LIGHT, False, 20),
        ("  → Login items, LaunchAgents, LaunchDaemons", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ("$ knockknock", ACCENT_GREEN, True, 22),
        ("  → Persistence mechanism baseline scan", TEXT_LIGHT, False, 20),
        ("  → Launch items, browser extensions, kernel extensions", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ("Notification database state captured", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ("This becomes our \"before\" photo — the clean room.", ACCENT_AMBER, False, 20),
    ], font_name=FONT_NAME)


    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Describe the first phase of the operation: Reconnaissance. '
                       'This involves capturing a snapshot of the system state before any changes '
                       'are made.')


def slide_phase_install(prs):
    """
    Slide 19 — Installation & real-time monitoring.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "PHASE 2: INFILTRATION", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(11.5), Inches(5.5), [
        ("The asset enters the system. All eyes on it.", TEXT_WHITE, True, 24),
        ('', TEXT_DIM, False, 8),
        ("INSTALLATION:", ACCENT_RED, True, 20),
        ("  Munki managedsoftwareupdate  —or—  manual drag-and-drop / PKG", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ("REAL-TIME SURVEILLANCE:", ACCENT_RED, True, 20),
        ("  BlockBlock    → persistence mechanism alerts (unified log)", TEXT_LIGHT, False, 20),
        ("  LuLu          → network connections intercepted", TEXT_LIGHT, False, 20),
        ("  XProtect       → Apple's border patrol scanning", TEXT_LIGHT, False, 20),
        ("  RansomWhere   → watching for encryption behaviour", TEXT_LIGHT, False, 20),
        ("  OverSight      → camera / microphone access", TEXT_LIGHT, False, 20),
        ("  ReiKey         → keyboard event taps", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ("Any suspicious activity is flagged immediately.", ACCENT_AMBER, True, 22),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Describe the second phase of the operation: Infiltration. '
                       'This involves the asset entering the system and real-time monitoring '
                       'for any suspicious activity.')


def slide_phase_scanning(prs):
    """
    Slide 20 — Package & binary scanning.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "PHASE 3: INTERROGATION", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(5.8), Inches(5.0), [
        ("VIRUSTOTAL", ACCENT_AMBER, True, 26),
        ('', TEXT_DIM, False, 6),
        ("SHA-256 hash lookup", TEXT_LIGHT, False, 20),
        ("→ submits new files for analysis", TEXT_LIGHT, False, 20),
        ("→ 70+ antivirus engines", TEXT_LIGHT, False, 20),
        ("→ files up to 650MB", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 6),
        ("LuLu intercepts → URLs/IPs", TEXT_LIGHT, False, 20),
        ("also sent to VT", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ('"Running the asset through', TEXT_DIM, False, 18),
        (' 70+ intelligence agencies"', TEXT_DIM, False, 18),
    ], font_name=FONT_NAME)

    _add_multiline(slide, Inches(7.0), Inches(1.5), Inches(5.8), Inches(5.0), [
        ("JAMF THREATLABS", ACCENT_AMBER, True, 26),
        ('', TEXT_DIM, False, 6),
        ("Mach-O binary deep analysis", TEXT_LIGHT, False, 20),
        ("→ threat levels: clean /", TEXT_LIGHT, False, 20),
        ("  suspicious / malicious", TEXT_LIGHT, False, 20),
        ("→ YARA rule matching", TEXT_LIGHT, False, 20),
        ("→ developer info extraction", TEXT_LIGHT, False, 20),
        ("→ parallel scanning (batches)", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ('"The binary polygraph test"', TEXT_DIM, False, 18),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Describe the third phase of the operation: Interrogation. '
                       'This involves scanning packages and binaries for potential threats.')


def slide_phase_postinstall(prs):
    """
    Slide 21 — Post-install analysis.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "PHASE 4: DAMAGE ASSESSMENT", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(11.5), Inches(5.5), [
        ("Compare the before and after photos.", TEXT_WHITE, True, 24),
        ('', TEXT_DIM, False, 8),
        ("BTM DIFF:", ACCENT_RED, True, 20),
        ("  New login items — managed vs non-managed", TEXT_LIGHT, False, 20),
        ("  LaunchAgents / LaunchDaemons installed", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 6),
        ("KNOCKKNOCK DELTA:", ACCENT_RED, True, 20),
        ("  New, modified, or removed persistence items", TEXT_LIGHT, False, 20),
        ("  Checking for sleeper agents left behind", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 6),
        ("SYSTEM CHANGES:", ACCENT_RED, True, 20),
        ("  System extensions, kernel extensions", TEXT_LIGHT, False, 20),
        ("  File system modifications", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 6),
        ("CODE SIGNING:", ACCENT_RED, True, 20),
        ("  Signature verification, certificate chain, trust evaluation", TEXT_LIGHT, False, 20),
        ("  Entitlements (camera, mic, screen recording, accessibility)", TEXT_LIGHT, False, 20),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Describe the fourth phase of the operation: Damage Assessment. This '
                       'involves comparing the System State before and after installation to '
                       'identify any changes or suspicious activity.')


def slide_phase_profiles(prs):
    """
    Slide 22 — Profile generation.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "PHASE 5: CLEARANCE PAPERS", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_textbox(slide, Inches(0.8), Inches(1.4), Inches(11), Inches(0.8),
                 "Auto-generated based on what the asset actually needs:", 22, TEXT_WHITE,
                 font_name=FONT_NAME)

    profiles = [
        ("PPPC", "Privacy Preferences Policy Control"),
        ("Notifications", "Notification allowlisting"),
        ("System Extensions", "Network / endpoint security extensions"),
        ("Managed Login Items", "LaunchAgents, LaunchDaemons, apps"),
        ("Screen Recording", "Screen capture permissions"),
        ("Content Filters", "Network content filtering"),
        ("Kernel Extensions", "Legacy kext requirements"),
    ]

    y = Inches(2.5)
    for name, desc in profiles:
        _add_textbox(slide, Inches(1.0), y, Inches(4.5), Inches(0.4),
                     f"  ✓  {name}", 20, ACCENT_GREEN, True, font_name=FONT_NAME)
        _add_textbox(slide, Inches(5.8), y, Inches(6.5), Inches(0.4),
                     desc, 20, TEXT_LIGHT, font_name=FONT_NAME)
        y += Inches(0.52)

    _add_multiline(slide, Inches(0.8), Inches(6.2), Inches(11.5), Inches(1.0), [
        ("+ Extension Attribute scripts", TEXT_DIM, False, 18),
        ("+ Intelligent merging of duplicate profiles", TEXT_DIM, False, 18),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Describe the fifth phase of the operation: Clearance Papers. This '
                       'involves generating the necessary profiles and configurations based on the '
                       'asset\'s requirements.')



def slide_the_dossier(prs):
    """
    Slide — The Dossier: header + System Info + Rosetta.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8), "PHASE 6: THE DOSSIER", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.21), Inches(11.5),
        Inches(1.0), [
            ("# Jamf Auto Update Software Title "
             "Installation Test Report",
             ACCENT_GREEN, True, 18),
            ("Generated: 2026-04-18 12:34:03",
             TEXT_DIM, False, 15),
            ("Application: EpidemicSound (x86_64) "
             "(version: 1.18.10)",
             TEXT_LIGHT, False, 15),
        ], font_name=FONT_NAME, line_spacing=1.2)

    _add_multiline(
        slide, Inches(0.75), Inches(2.27), Inches(5.8),
        Inches(5.0544), [
            ("## System Information",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Detected macOS version: 26.4.1 "
             "(macOS Tahoe)",
             TEXT_LIGHT, False, 14),
            ("Detected architecture: x86_64",
             TEXT_LIGHT, False, 14),
            ("Detected Munki version: 6.6.5.4711",
             TEXT_LIGHT, False, 14),
            ("Console user: test",
             TEXT_LIGHT, False, 14),
            ("User admin status: Administrator",
             TEXT_LIGHT, False, 14),
            ("Model Identifier: MacBookPro16,1",
             TEXT_LIGHT, False, 14),
            ("System type: Physical Hardware "
             "\u2014 MacBook Pro",
             TEXT_LIGHT, False, 14),
            ("Serial number: C02FV960MD6R",
             TEXT_LIGHT, False, 14),
            ('', TEXT_DIM, False, 5),
            ("Security tools detected: 7 tools",
             ACCENT_AMBER, True, 15),
            ("  BlockBlock: 2.4.2",
             TEXT_DIM, False, 14),
            ("  LuLu: 4.3.1",
             TEXT_DIM, False, 14),
            ("  ReiKey: 1.4.2",
             TEXT_DIM, False, 14),
            ("  RansomWhere: 2.1.2",
             TEXT_DIM, False, 14),
            ("  OverSight: 2.4.0",
             TEXT_DIM, False, 14),
            ("  XProtect: 5338 "
             "(Installed: 2026-04-13 07:33:53)",
             TEXT_DIM, False, 14),
            ("  KnockKnock: 4.0.3",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 5),
            ("XProtect Configuration:",
             TEXT_LIGHT, False, 14),
            ("  Launch scans: enabled",
             TEXT_DIM, False, 14),
            ("  Background scans: enabled",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(2.27), Inches(5.5),
        Inches(1.8), [
            ("## Rosetta Compatibility",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Epidemic Sound.app:",
             TEXT_LIGHT, False, 15),
            ("  Runs natively on Apple Silicon",
             ACCENT_GREEN, False, 14),
            ("  Intel binary (x86_64)",
             TEXT_DIM, False, 14),
            ("  runs natively on Intel, requires "
             "Rosetta 2 on Apple Silicon",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - A comprehensive markdown report is '
        'generated after every title test. It\u2019s '
        'important to note that it\u2019s not '
        'specifically designed for pass/fail scenarios, '
        'it\u2019s designed to give you the information '
        'needed to investigate anything that that you '
        'find suspicious. Unless of course every VT '
        'vendor flags it as malicious, probably safe to '
        'automatically fail that! \n\n'
        'This is a real example from testing Epidemic '
        'Sound 1.18.10. Starting with system info \u2013 '
        'the test Mac, detected tools, and architecture.')


def slide_the_dossier_2(prs):
    """
    Slide — Dossier: Catalog + Installation + Tests +
    Package Analysis.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8), "THE DOSSIER", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(5.8),
        Inches(3.53), [
            ("## Catalog Validation",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Uninstall Method: "
             "remove_copied_items",
             TEXT_LIGHT, False, 14),
            ("Found 1 item(s) in installs array",
             TEXT_LIGHT, False, 14),
            ('', TEXT_DIM, False, 5),
            ("Validating installs array item 1:",
             TEXT_LIGHT, False, 14),
            ("  Found minosversion: 12.0",
             TEXT_DIM, False, 14),
            ("\u2705 CFBundleShortVersionString "
             "matches (1.18.10)",
             TEXT_DIM, False, 14),
            ("  Path: /Applications/"
             "Epidemic Sound.app",
             TEXT_DIM, False, 14),
            ("  Type: application",
             TEXT_DIM, False, 14),
            ("  Bundle ID: "
             "com.electron.epidemic-sound",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 5),
            ("OS Version Validation:",
             TEXT_LIGHT, False, 14),
            ("  Found 1 minosversion(s): 12.0",
             TEXT_DIM, False, 14),
            ("\u2705 Highest minosversion matches "
             "minimum_os_version (12.0)",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(1.3), Inches(5.5),
        Inches(2.03), [
            ("## Installation Details",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Selected application: EpidemicSound",
             TEXT_LIGHT, False, 14),
            ("Version: 1.18.10",
             TEXT_LIGHT, False, 14),
            ("Architecture: (x86_64)",
             TEXT_LIGHT, False, 14),
            ("Installation started: "
             "2026-04-18 12:34:11",
             TEXT_LIGHT, False, 14),
            ("\u2192 The software was successfully "
             "installed.",
             ACCENT_GREEN, False, 14),
            ("Installation completed: "
             "2026-04-18 12:39:20",
             TEXT_LIGHT, False, 14),
            ("Installation duration: 5m 8s",
             TEXT_LIGHT, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(0.8), Inches(4.84), Inches(5.8),
        Inches(2.28), [
            ("## Test Results",
             ACCENT_GREEN, True, 11),
            ('', TEXT_DIM, False, 5),
            ("\u2705 Successfully installed and "
             "tested EpidemicSound (version: 1.18.10)",
             TEXT_LIGHT, False, 11),
            ('', TEXT_DIM, False, 5),
            ("Loop Install Test: PASSED",
             ACCENT_GREEN, True, 11),
            ("  \u2705 Performed post-install "
             "looping installation check",
             TEXT_DIM, False, 11),
            ("  \u2705 No reinstallation required",
             TEXT_DIM, False, 11),
            ('', TEXT_DIM, False, 5),
            ("Loop Uninstall Test: PASSED",
             ACCENT_GREEN, True, 11),
            ("  \u2705 Performed post-uninstall "
             "looping uninstallation check",
             TEXT_DIM, False, 11),
            ("  \u2705 No re-uninstallation "
             "required",
             TEXT_DIM, False, 11),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(4.5), Inches(5.5),
        Inches(1.48), [
            ("## Package Analysis",
             ACCENT_GREEN, True, 11),
            ('', TEXT_DIM, False, 5),
            ("Packages analysed: 1",
             TEXT_LIGHT, False, 11),
            ("Total deprecated dependency "
             "issues: 0",
             TEXT_LIGHT, False, 11),
            ("Critical issues (Python 2): 0",
             TEXT_LIGHT, False, 11),
            ('', TEXT_DIM, False, 5),
            ("\u2705 No deprecated dependencies "
             "found.",
             ACCENT_GREEN, False, 11),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - Catalog validation confirms the munki '
        'pkginfo is well-formed \u2013 installs array, '
        'version matching, min OS version. Installation '
        'took 5 minutes 8 seconds, passed install '
        'and uninstall looping tests. No '
        'deprecated dependencies found.')


def slide_the_dossier_3(prs):
    """
    Slide — Dossier: VirusTotal Malware Analysis.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8),
        "THE DOSSIER: SECURITY EVENTS", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(11.5),
        Inches(6.0), [
            ("## VirusTotal Malware Analysis",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Files analyzed: 1",
             TEXT_LIGHT, False, 14),
            ("Clean files: 1",
             TEXT_LIGHT, False, 14),
            ("Malicious files: 0",
             TEXT_LIGHT, False, 14),
            ("Suspicious files: 0",
             TEXT_LIGHT, False, 14),
            ("Manual check required: 0",
             TEXT_LIGHT, False, 14),
            ("Analysis errors: 0",
             TEXT_LIGHT, False, 14),
            ('', TEXT_DIM, False, 5),
            ("Detailed analysis results:",
             TEXT_LIGHT, True, 15),
            ('', TEXT_DIM, False, 5),
            ("File: EpidemicSound-1.18.10.dmg "
             "(127.28 MB)",
             TEXT_LIGHT, False, 15),
            ("  Status: \u2705 CLEAN "
             "(0/62 detections)",
             ACCENT_GREEN, False, 14),
            ("  Report URL: https://www."
             "virustotal.com/gui/file/"
             "b8b6e8494797d73ee2c0e8c4739d95"
             "b07ad0f3fc8f598dd50aa934fde3b1"
             "0fcf",
             TEXT_DIM, False, 12),
            ("  Analysis type: file",
             TEXT_DIM, False, 14),
            ("  SHA-256: b8b6e8494797d73e"
             "e2c0e8c4739d95b07ad0f3fc8f598d"
             "d50aa934fde3b10fcf",
             TEXT_DIM, False, 12),
            ('', TEXT_DIM, False, 5),
            ("\u2705 All analyzed files passed "
             "malware screening.",
             ACCENT_GREEN, True, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - VirusTotal scanned the DMG \u2013 '
        'clean across all 62 engines. Full SHA-256 '
        'hash and report URL shown for '
        'verification.')


def slide_the_dossier_3b(prs):
    """
    Slide — Dossier: ThreatLabs Binary Analysis.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8),
        "THE DOSSIER: SECURITY EVENTS", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(11.5),
        Inches(1.8), [
            ("## Jamf ThreatLabs Binary Analysis",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Total binaries extracted: 5",
             TEXT_LIGHT, False, 14),
            ("Binaries submitted: 5   "
             "Skipped: 0",
             TEXT_LIGHT, False, 14),
            ('', TEXT_DIM, False, 5),
            ("Results:  Clean: 5  Suspicious: 0"
             "  Malicious: 0  Pending: 0",
             ACCENT_GREEN, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(0.26), Inches(3.3), Inches(6.74),
        Inches(2.76), [
            ("Detailed Binary Analysis:",
             TEXT_LIGHT, True, 15),
            ('', TEXT_DIM, False, 5),
            ("Binary: Epidemic Sound",
             TEXT_LIGHT, True, 14),
            ("  Source: EpidemicSound-1.18.10.dmg",
             TEXT_DIM, False, 13),
            ("  App Bundle: Epidemic Sound.app",
             TEXT_DIM, False, 13),
            ("  Path: Epidemic Sound",
             TEXT_DIM, False, 13),
            ('', TEXT_DIM, False, 5),
            ('', TEXT_DIM, False, 5),
            ("  SHA-256: 9b4431c359fbbc6c76"
             "3917e227a7f0c4",
             TEXT_DIM, False, 12),
            ("    3635320136d9cad7f98c8d"
             "2b0caf6715",
             TEXT_DIM, False, 12),
            ("  Submission ID: 09a64670-"
             "c97b-4d3f-95c2-3bd089925a39",
             TEXT_DIM, False, 12),
            ("  Threat Level: \u2705 CLEAN",
             ACCENT_GREEN, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(3.3), Inches(6.07),
        Inches(2.49), [
            ('', TEXT_DIM, False, 15),
            ('', TEXT_DIM, False, 5),
            ("Binary: Epidemic Sound Helper",
             TEXT_LIGHT, True, 14),
            ("  Source: EpidemicSound-1.18.10.dmg",
             TEXT_DIM, False, 13),
            ("  App Bundle: Epidemic Sound.app",
             TEXT_DIM, False, 13),
            ("  Path: Epidemic Sound Helper.app/"
             "Contents/",
             TEXT_DIM, False, 13),
            ("    MacOS/Epidemic Sound Helper",
             TEXT_DIM, False, 13),
            ('', TEXT_DIM, False, 5),
            ("  SHA-256: 32d1289e1bb71d2e84"
             "173fe4c3c7543f",
             TEXT_DIM, False, 12),
            ("    be43b60621ab1e7a7fd539"
             "2d851cd648",
             TEXT_DIM, False, 12),
            ("  Submission ID: b963e8a8-"
             "b820-4577-abe7-23cd03eecf86",
             TEXT_DIM, False, 12),
            ("  Threat Level: \u2705 CLEAN",
             ACCENT_GREEN, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(0.8), Inches(7.0), Inches(11.5),
        Inches(0.5), [
            ("\u2705 All analyzed binaries passed "
             "security screening.",
             ACCENT_GREEN, True, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - Threat Labs extracted and scanned 5 '
        'Mach-O binaries from the app bundle. '
        'Showing two in full detail \u2013 the '
        'main Epidemic Sound binary and the Helper '
        'app. All 5 came back clean.')


def slide_the_dossier_4(prs):
    """
    Slide — Dossier: KnockKnock + BlockBlock + DHS.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8),
        "THE DOSSIER: SECURITY EVENTS", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(5.8),
        Inches(2.9199), [
            ("## KnockKnock Persistence Analysis",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Scan Summary:",
             TEXT_LIGHT, True, 14),
            ("  Baseline items: 52",
             TEXT_LIGHT, False, 14),
            ("  Post-install items: 52",
             TEXT_LIGHT, False, 14),
            ('', TEXT_DIM, False, 5),
            ("Changes Detected:",
             TEXT_LIGHT, True, 14),
            ("  New persistence items: 0",
             TEXT_DIM, False, 14),
            ("  Modified items: 0",
             TEXT_DIM, False, 14),
            ("  Removed items: 0",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(1.3), Inches(5.5),
        Inches(2.6226), [
            ("## BlockBlock",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Installation Phase Events:",
             TEXT_LIGHT, True, 14),
            ('', TEXT_DIM, False, 3),
            ("[2026-04-18 12:34:50] "
             "BlockBlock allowed:",
             TEXT_LIGHT, False, 14),
            ("  Unknown application",
             TEXT_LIGHT, False, 14),
            ("  Path: Unknown application",
             TEXT_DIM, False, 13),
            ("  Action: user_allowed",
             TEXT_DIM, False, 13),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(4.0), Inches(5.5),
        Inches(3.4584), [
            ("## DHS",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Vulnerable Applications:",
             ACCENT_AMBER, True, 14),
            ('', TEXT_DIM, False, 3),
            ("Binary: /Applications/"
             "BBEdit.app/Contents/",
             TEXT_DIM, False, 13),
            ("  MacOS/BBEdit",
             TEXT_DIM, False, 13),
            ("  Issue: rpath",
             TEXT_DIM, False, 13),
            ("  Dylib: /Applications/"
             "BBEdit.app/Contents/",
             TEXT_DIM, False, 13),
            ("    Frameworks/CrashReporter"
             ".framework/",
             TEXT_DIM, False, 13),
            ("    Versions/A/CrashReporter",
             TEXT_DIM, False, 13),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - KnockKnock found no new persistence '
        'items \u2013 baseline stayed at 52. '
        'BlockBlock allowed an unknown application '
        'event during installation. DHS flagged a '
        'BBEdit rpath vulnerability \u2013 not '
        'related to Epidemic Sound.')


def slide_the_dossier_4b(prs):
    """
    Slide — Dossier: VT Network + LuLu + XProtect +
    RansomWhere + OverSight + ReiKey.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8),
        "THE DOSSIER: SECURITY EVENTS", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(5.8),
        Inches(3.0), [
            ("## VirusTotal Network Analysis",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("[12:45:09] Network scan:",
             TEXT_LIGHT, False, 14),
            ("  142.250.140.95 - clean "
             "(0/98 vendors flagged)",
             TEXT_LIGHT, False, 14),
            ("  \u2705 Connection appears clean",
             ACCENT_GREEN, False, 14),
            ("  (not flagged by any vendors)",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 5),
            ("[12:45:09] Network scan:",
             TEXT_LIGHT, False, 14),
            ("  es-plugin-builds.storage."
             "googleapis.com",
             TEXT_LIGHT, False, 14),
            ("  clean (0/91 vendors flagged)",
             TEXT_LIGHT, False, 14),
            ("  \u2705 Connection appears clean",
             ACCENT_GREEN, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(1.3), Inches(5.5),
        Inches(3.0), [
            ("## LuLu",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("[2026-04-18 12:44:19] LuLu "
             "allowed:",
             TEXT_LIGHT, False, 14),
            ("  Epidemic Sound Helper.app",
             TEXT_LIGHT, False, 14),
            ("  Application Path: "
             "/Applications/Epidemic Sound.app/",
             TEXT_DIM, False, 13),
            ("    Contents/Frameworks/"
             "Epidemic Sound Helper.app",
             TEXT_DIM, False, 13),
            ("  Network Connection: "
             "142.250.140.95:443",
             TEXT_DIM, False, 13),
            ('', TEXT_DIM, False, 5),
            ("[2026-04-18 12:44:21] LuLu "
             "allowed:",
             TEXT_LIGHT, False, 14),
            ("  Epidemic Sound.app",
             TEXT_LIGHT, False, 14),
            ("  Network Connection: "
             "es-plugin-builds.storage.",
             TEXT_DIM, False, 13),
            ("    googleapis.com:443",
             TEXT_DIM, False, 13),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(0.8), Inches(4.5), Inches(5.8),
        Inches(2.8), [
            ("## XProtect",
             ACCENT_GREEN, True, 17),
            ("  No XProtect events detected",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 5),
            ("## RansomWhere",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 3),
            ("RansomWhere Alert #1",
             ACCENT_AMBER, True, 14),
            ("  Timestamp: 2026-04-18 12:44:27",
             TEXT_DIM, False, 13),
            ("  \u2705 User allowed application",
             ACCENT_GREEN, False, 13),
            ("  Severity: high",
             TEXT_DIM, False, 13),
            ("  Path: /Applications/"
             "Epidemic Sound.app/",
             TEXT_DIM, False, 13),
            ("    Contents/Frameworks/"
             "Epidemic Sound",
             TEXT_DIM, False, 13),
            ("    Helper.app/.../Epidemic "
             "Sound Helper",
             TEXT_DIM, False, 13),
            ("  PID: 95396",
             TEXT_DIM, False, 13),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(4.5), Inches(5.5),
        Inches(2.8), [
            ("## OverSight",
             ACCENT_GREEN, True, 17),
            ("  No camera/microphone access "
             "events detected",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 5),
            ("## ReiKey",
             ACCENT_GREEN, True, 17),
            ("  No keylogger events detected",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - VirusTotal Network scan found two '
        'connections \u2013 one to a Google IP and one '
        'to googleapis.com, both clean. LuLu confirmed '
        'the same connections from the Helper app and '
        'main app. RansomWhere flagged the Helper '
        'creating encrypted files but user allowed it. '
        'No events from XProtect, OverSight, or ReiKey.')


def slide_the_dossier_5(prs):
    """
    Slide — Dossier: System Changes.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8),
        "THE DOSSIER: SYSTEM CHANGES", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(11.5),
        Inches(0.6), [
            ("## System Extensions",
             ACCENT_GREEN, True, 17),
            ("  No System Extensions found",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(0.8), Inches(2.1), Inches(5.8),
        Inches(4.0), [
            ("## Managed Login Items",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("No login items changes detected",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(2.1), Inches(5.5),
        Inches(1.5), [
            ("## Notification Changes",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Application: "
             "com.electron.epidemic-sound",
             TEXT_LIGHT, False, 14),
            ("  New notification permission: "
             "Inactive",
             TEXT_DIM, False, 14),
            ("  Path: /Applications/"
             "Epidemic Sound.app",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - System changes after installation. No '
        'system extensions. No login item changes. '
        'One new notification permission registered '
        'for com.electron.epidemic-sound but inactive.')


def slide_the_dossier_6(prs):
    """
    Slide — Dossier: Uninstall + Code Signing.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8), "THE DOSSIER: RESULTS", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(5.8),
        Inches(2.3197), [
            ("## Uninstall Results",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("\u2705 Successfully uninstalled "
             "EpidemicSound",
             ACCENT_GREEN, True, 15),
            ('', TEXT_DIM, False, 5),
            ("Uninstalled at: 12:55:21",
             TEXT_LIGHT, False, 14),
            ("Uninstallation duration: 32s",
             TEXT_LIGHT, False, 14),
            ('', TEXT_DIM, False, 5),
            ("\u2705 Successfully uninstalled "
             "EpidemicSound (version: 1.18.10)",
             ACCENT_GREEN, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    _add_multiline(
        slide, Inches(7.0), Inches(1.3), Inches(5.5),
        Inches(5.8146), [
            ("## Code Signing Results",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 5),
            ("Application: /Applications/"
             "Epidemic Sound.app",
             TEXT_LIGHT, False, 14),
            ('', TEXT_DIM, False, 5),
            ("Executable=.../Epidemic Sound",
             TEXT_DIM, False, 13),
            ("Identifier="
             "com.electron.epidemic-sound",
             TEXT_DIM, False, 13),
            ("Format=app bundle with Mach-O "
             "thin (x86_64)",
             TEXT_DIM, False, 13),
            ("CodeDirectory v=20500 "
             "flags=0x10000(runtime)",
             TEXT_DIM, False, 13),
            ("Signature size=9054",
             TEXT_DIM, False, 13),
            ('', TEXT_DIM, False, 3),
            ("Authority=Developer ID "
             "Application:",
             TEXT_LIGHT, False, 13),
            ("  Epidemic Sound AB "
             "(LE95XJ5KXM)",
             TEXT_LIGHT, False, 13),
            ("Authority=Developer ID "
             "Certification Authority",
             TEXT_DIM, False, 13),
            ("Authority=Apple Root CA",
             TEXT_DIM, False, 13),
            ('', TEXT_DIM, False, 3),
            ("Timestamp=Mar 3, 2026 "
             "at 2:32:29 PM",
             TEXT_DIM, False, 13),
            ("Notarization Ticket=stapled",
             TEXT_DIM, False, 13),
            ("TeamIdentifier=LE95XJ5KXM",
             TEXT_DIM, False, 13),
            ("Runtime Version=26.0.0",
             TEXT_DIM, False, 13),
            ("Sealed Resources: rules=13 "
             "files=15",
             TEXT_DIM, False, 13),
            ('', TEXT_DIM, False, 3),
            ("BundleID: "
             "com.electron.epidemic-sound",
             TEXT_LIGHT, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - Uninstall succeeded \u2013 Epidemic '
        'Sound was cleanly removed in 32 seconds. '
        'Code signing looks solid \u2013 properly '
        'signed by Epidemic Sound AB with Developer '
        'ID, notarized with stapled ticket, '
        'hardened runtime enabled.')


def slide_the_dossier_7(prs):
    """
    Slide — Dossier: Configuration Profiles.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8),
        "THE DOSSIER: CONFIG PROFILES", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(
        slide, Inches(0.8), Inches(1.3), Inches(5.8),
        Inches(3.7417), [
            ("## Configuration Profiles Generated",
             ACCENT_GREEN, True, 17),
            ('', TEXT_DIM, False, 7),
            ("Profile: Screen Recording",
             TEXT_LIGHT, True, 16),
            ("Filename: Screen Recording - "
             "Allow EpidemicSound.mobileconfig",
             TEXT_DIM, False, 14),
            ("Applications: Epidemic Sound.app",
             TEXT_DIM, False, 14),
            ("Bundle ID: "
             "com.electron.epidemic-sound",
             TEXT_DIM, False, 14),
            ('', TEXT_DIM, False, 5),
            ("Profile: Notifications",
             TEXT_LIGHT, True, 16),
            ("Filename: Notifications - "
             "Allow EpidemicSound.mobileconfig",
             TEXT_DIM, False, 14),
            ("Applications: Epidemic Sound.app",
             TEXT_DIM, False, 14),
            ("Bundle ID: "
             "com.electron.epidemic-sound",
             TEXT_DIM, False, 14),
        ], font_name=FONT_NAME, line_spacing=1.1)

    # Stamp removed per user edit

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = (
        'PC - Two configuration profiles '
        'auto-generated: Screen Recording and '
        'Notifications. Both for Epidemic Sound. '
        'These are ready to upload to Jamf Pro '
        '\u2013 saving hours of manual profile '
        'creation.')


def slide_demo_intro(prs):
    """
    Slide 24 — Demo transition.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(2.0), Inches(11.7), Inches(1.5),
                 "FIELD OPERATION", 64, ACCENT_RED, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_divider(slide, Inches(3.6))

    _add_textbox(slide, Inches(0.8), Inches(4.0), Inches(11.7), Inches(1.0),
                 "[ LIVE DEMO ]", 40, ACCENT_AMBER, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_textbox(slide, Inches(0.8), Inches(5.2), Inches(11.7), Inches(0.6),
                 '"Trust, but verify" — let\'s verify, live.', 22, TEXT_DIM,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC and BT - Transition to the live demo portion of the presentation. Set the stage '
                       'for showing the live demonstration.')


def slide_demo_video(prs):
    """
    Slide — Embedded demo screen recording.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(
        slide, Inches(0.8), Inches(0.3), Inches(12),
        Inches(0.8),
        "FIELD OPERATION: DEMO", 44,
        ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    script_dir = os.path.dirname(os.path.abspath(__file__))
    video_path = os.path.join(
        script_dir,
        "Screen Recording 2026-04-19 at 21.31.18.mov")

    if os.path.exists(video_path):
        slide.shapes.add_movie(
            video_path,
            Inches(0.8), Inches(1.4),
            Inches(11.7), Inches(5.8),
            mime_type='video/quicktime')
    else:
        _add_textbox(
            slide, Inches(0.8), Inches(3.0), Inches(11.7),
            Inches(1.0),
            "[ VIDEO NOT FOUND ]", 32, ACCENT_AMBER,
            True, alignment=PP_ALIGN.CENTER,
            font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    tf = notes_slide.notes_text_frame
    tf.text = ('PC and BT - Play the demo video. '
               'Walk through the screen recording '
               'showing InstallAudit in action.')


def slide_what_weve_caught(prs):
    """
    Slide 25 — Real findings.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "INTELLIGENCE GATHERED", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_textbox(slide, Inches(0.8), Inches(1.4), Inches(11), Inches(0.6),
                 "Real findings during testing (update with your examples):", 22, TEXT_WHITE,
                 font_name=FONT_NAME)

    findings = [
        ("⚠", "Unexpected persistence mechanisms", ACCENT_AMBER),
        ("⚠", "Suspicious outbound network connections", ACCENT_AMBER),
        ("⚠", "Unsigned or ad-hoc signed binaries", ACCENT_AMBER),
        ("⚠", "Deprecated APIs or insecure installer scripts", ACCENT_AMBER),
        ("⚠", "Hidden LaunchDaemons running as root", ACCENT_AMBER),
        ("⚠", "Overly broad entitlements (accessibility, screen recording)", ACCENT_AMBER),
        ("⚠", "[Add your own real examples here]", TEXT_DIM),
        ("⚠", "[Add your own real examples here]", TEXT_DIM),
    ]

    y = Inches(2.4)
    for icon, text, clr in findings:
        _add_textbox(slide, Inches(1.0), y, Inches(11), Inches(0.45),
                     f"  {icon}  {text}", 22, clr, font_name=FONT_NAME)
        y += Inches(0.55)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Share real findings from your testing to illustrate the value of the '
                       'software verification process.')


def slide_getting_started(prs):
    """
    Slide 26 — How to get started.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "RECRUITMENT", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.8), Inches(1.5), Inches(11.5), Inches(5.63), [
        ("REQUIREMENTS:", ACCENT_RED, True, 22),
        ("  macOS 11+  ·  Python 3.9+  ·  pure stdlib (no pip installs)", TEXT_LIGHT, False, 20),
        ("  Xcode Command Line Tools", TEXT_LIGHT, False, 20),
        ("  Test hardware (or VM if none available)", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
        ("SETUP:", ACCENT_RED, True, 22),
        ("  $ git clone https://github.com/paul-cossey/macaduk-2026-trust-but-verify", ACCENT_GREEN, False, 20),
        ("  $ python3 configure.py --edit", ACCENT_GREEN, False, 20),
        ("  $ sudo python3 main.py", ACCENT_GREEN, False, 20),
        ('', TEXT_DIM, False, 8),
        ("RECOMMENDED:", ACCENT_RED, True, 22),
        ("  Install Objective-See tools for full coverage", TEXT_LIGHT, False, 20),
        ("  Free VirusTotal API key (public tier works)", TEXT_LIGHT, False, 20),
        ("  Jamf ThreatLabs key (free for Jamf customers, beta)", TEXT_LIGHT, False, 20),
        ('', TEXT_DIM, False, 8),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Provide guidance on how to get started with implementing the software '
                       'verification process.')


def slide_whats_next(prs):
    """
    Slide 27 — Roadmap.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(12), Inches(0.8),
                 "FUTURE OPS", 44, ACCENT_RED, True, font_name=FONT_NAME)
    _add_divider(slide, Inches(1.1))

    _add_multiline(slide, Inches(0.44), Inches(1.5), Inches(11.86), Inches(2.74), [
        ("What's on the roadmap:", TEXT_WHITE, True, 24),
        ('', TEXT_DIM, False, 10),
        ("  \u2591  Remove Python dependency \u2014 port to Swift",
         TEXT_LIGHT, False, 22),
        ("  \u2591  Convert to an LLM Skill / AI agent workflow",
         TEXT_LIGHT, False, 22),
        ("  \u2591  Persistence evaluation ",
         TEXT_LIGHT, False, 22),
        ("  \u2591  Community contributions welcome",
         TEXT_LIGHT, False, 22),
        ('', TEXT_DIM, False, 10),
    ], font_name=FONT_NAME)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC - Share your roadmap for future development and improvements to the '
                       'software verification process.')


def slide_thank_you(prs):
    """
    Slide 28 — Thank you / Q&A.
    """
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_textbox(slide, Inches(0.8), Inches(0.3), Inches(11.7), Inches(0.8),
                 "END OF BRIEFING", 48, ACCENT_RED, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_divider(slide, Inches(1.1))

    _add_textbox(slide, Inches(0.8), Inches(1.3), Inches(11.7), Inches(0.7),
                 '"Trust, but verify."', 32, TEXT_WHITE, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_multiline(
        slide, Inches(0.7302), Inches(2.7558), Inches(11.7),
        Inches(0.7742), [
            ("GitHub: jamf.it/kdt6wC", TEXT_LIGHT, False, 40),
        ], font_name=FONT_NAME, line_spacing=1.1,
        alignment=PP_ALIGN.CENTER)

    _add_textbox(slide, Inches(0.8), Inches(5.5),
                 Inches(11.7), Inches(0.8),
                 "QUESTIONS?", 44, ACCENT_AMBER, True,
                 alignment=PP_ALIGN.CENTER, font_name=FONT_NAME)

    _add_stamp(slide, "DECLASSIFIED", Inches(8.2498), Inches(3.6765), STAMP_GREEN, 32, -10)

    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = ('PC and BT - Q&A slide. Provide contact information and links to resources '
                       'for further learning.\n\n'
                       'Titles we\u2019d declined to add\n\n'
                       'Titles we removed \n'
                       '- Ngrok (unable to reliably scan due to constant flagging '
                       'by VT vendors as a hacking tool) ')


# ── Build the deck ──────────────────────────────────────────────

print("Building slides...")

slide_title(prs)
slide_agents(prs)
slide_jamf_auto_update(prs)
slide_links(prs)
slide_reagan_quote(prs)
slide_poll_results(prs)
slide_the_problem(prs)
slide_code_signature_verification(prs)
slide_code_signature_verification_example_1(prs)
slide_code_signature_verification_example_2(prs)
slide_code_signature_verification_example_3(prs)
slide_code_signature_verification(prs)
slide_the_evolving_problem(prs)
slide_mission_brief_history(prs)
slide_mission_brief_checklist(prs)
slide_mission_brief(prs)
slide_toolbelt(prs)
slide_tool_virustotal(prs)
slide_tool_threatlabs(prs)
slide_tool_threatlabs_dashboard(prs)
slide_tool_threatlabs_results(prs)
slide_tool_lulu(prs)
slide_tool_blockblock(prs)
slide_tool_knockknock(prs)
slide_tool_ransomwhere(prs)
slide_tool_oversight(prs)
slide_tool_reikey(prs)
slide_tool_dhs(prs)
slide_tool_xprotect(prs)
slide_tool_config_profiles(prs)
slide_tool_config_profiles_entitlements(prs)
slide_the_dossier(prs)
slide_the_dossier_2(prs)
slide_the_dossier_3(prs)
slide_the_dossier_3b(prs)
slide_the_dossier_4(prs)
slide_the_dossier_4b(prs)
slide_the_dossier_5(prs)
slide_the_dossier_6(prs)
slide_the_dossier_7(prs)
slide_demo_intro(prs)
slide_demo_video(prs)
slide_getting_started(prs)
slide_whats_next(prs)
slide_thank_you(prs)

print("Adding animations...")
for slide in prs.slides:
    _animate_slide(slide)

output = "Trust_But_Verify_MacAD_UK_2026.pptx"
prs.save(output)
print(f"✅ Saved: {output}")
print(f"   {len(prs.slides)} slides")
print("   Open in Keynote to convert to .key format")
