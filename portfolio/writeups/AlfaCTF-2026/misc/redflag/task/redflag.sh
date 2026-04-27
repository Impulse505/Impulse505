#!/usr/bin/env bash
# RED FLAG: modern console-based tier list service

set -uo pipefail

trap '' INT TSTP QUIT TERM HUP

TIERLISTS_DIR="/data/tierlists"
CURRENT_USER=""
RESERVED_USERS="admin trail_yuki nastya_gorp oleg_runner marina_wild"
TITLE="Р Р•Р”-Р¤Р›РђР“: С‚РёСЂ-Р»РёСЃС‚С‹"

### helpers ###

msg() {
    whiptail --title "$TITLE" --msgbox "$1" 10 60
}

yesno() {
    whiptail --title "$TITLE" --yesno "$1" 10 60
}

input() {
    whiptail --title "$TITLE" --inputbox "$1" 10 60 "$2" 3>&1 1>&2 2>&3
}

### .meta helpers ###

meta_get() {
    local meta="$1/.meta"
    [[ -f "$meta" ]] || return 1
    grep "^$2=" "$meta" 2>/dev/null | head -1 | cut -d'=' -f2-
}

meta_set() {
    local meta="$1/.meta"
    if grep -q "^$2=" "$meta" 2>/dev/null; then
        local tmp
        tmp=$(mktemp)
        while IFS= read -r line; do
            if [[ "$line" == "$2="* ]]; then
                printf '%s=%s\n' "$2" "$3"
            else
                printf '%s\n' "$line"
            fi
        done < "$meta" > "$tmp"
        mv "$tmp" "$meta"
    else
        printf '%s=%s\n' "$2" "$3" >> "$meta"
    fi
}

is_owner() {
    local owner
    owner=$(meta_get "$1" "owner") || return 1
    [[ "$owner" == "$CURRENT_USER" ]]
}

is_collaborator() {
    local collabs
    collabs=$(meta_get "$1" "collaborators") || return 1
    [[ -z "$collabs" ]] && return 1
    local IFS=','
    for c in $collabs; do
        [[ "$c" == "$CURRENT_USER" ]] && return 0
    done
    return 1
}

can_edit() {
    is_owner "$1" || is_collaborator "$1"
}

is_restricted() {
    local restricted
    restricted=$(meta_get "$1" "restricted") || return 1
    [[ -z "$restricted" ]] && return 1
    local IFS=','
    for r in $restricted; do
        [[ "$r" == "$2" ]] && return 0
    done
    return 1
}

can_read_file() {
    if is_restricted "$1" "$2"; then
        is_owner "$1"
    else
        return 0
    fi
}

### login ###

do_login() {
    while true; do
        CURRENT_USER=$(input "Р’РІРµРґРёС‚Рµ РІР°С€Рµ РёРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ:" "") || exit 0

        if [[ -z "$CURRENT_USER" ]]; then
            msg "РРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РЅРµ РјРѕР¶РµС‚ Р±С‹С‚СЊ РїСѓСЃС‚С‹Рј."
            continue
        fi

        if [[ ! "$CURRENT_USER" =~ ^[a-zA-Z0-9_]+$ ]]; then
            msg "РРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РјРѕР¶РµС‚ СЃРѕРґРµСЂР¶Р°С‚СЊ С‚РѕР»СЊРєРѕ Р»Р°С‚РёРЅСЃРєРёРµ Р±СѓРєРІС‹, С†РёС„СЂС‹ Рё _"
            continue
        fi

        if [[ ${#CURRENT_USER} -lt 3 ]]; then
            msg "РРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РґРѕР»Р¶РЅРѕ Р±С‹С‚СЊ РЅРµ РєРѕСЂРѕС‡Рµ 3 СЃРёРјРІРѕР»РѕРІ."
            continue
        fi

        if [[ ${#CURRENT_USER} -gt 16 ]]; then
            msg "РРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РґРѕР»Р¶РЅРѕ Р±С‹С‚СЊ РЅРµ РґР»РёРЅРЅРµРµ 16 СЃРёРјРІРѕР»РѕРІ."
            continue
        fi

        local reserved=0
        for r in $RESERVED_USERS; do
            if [[ "$r" == "$CURRENT_USER" ]]; then
                reserved=1
                break
            fi
        done

        if [[ $reserved -eq 1 ]]; then
            msg "Р­С‚Рѕ РёРјСЏ СѓР¶Рµ Р·Р°РЅСЏС‚Рѕ. Р’С‹Р±РµСЂРёС‚Рµ РґСЂСѓРіРѕРµ."
            continue
        fi

        break
    done
}

### list tierlists ###

list_my_tierlists() {
    local items=()
    for d in "$TIERLISTS_DIR"/*/; do
        [[ -d "$d" ]] || continue
        local name
        name=$(basename "$d")
        local owner
        owner=$(meta_get "$d" "owner") || continue
        if [[ "$owner" == "$CURRENT_USER" ]] || is_collaborator "$d"; then
            items+=("$name" "@$owner")
        fi
    done

    if [[ ${#items[@]} -eq 0 ]]; then
        msg "РЈ РІР°СЃ РЅРµС‚ С‚РёСЂ-Р»РёСЃС‚РѕРІ."
        return
    fi

    local choice
    choice=$(whiptail --title "РњРѕРё С‚РёСЂ-Р»РёСЃС‚С‹" --menu "\nР’С‹Р±РµСЂРёС‚Рµ С‚РёСЂ-Р»РёСЃС‚:" 20 70 10 \
        "${items[@]}" 3>&1 1>&2 2>&3) || return

    view_tierlist "$TIERLISTS_DIR/$choice"
}

list_all_tierlists() {
    local items=()
    for d in "$TIERLISTS_DIR"/*/; do
        [[ -d "$d" ]] || continue
        [[ -f "$d/.meta" ]] || continue
        local name owner
        name=$(basename "$d")
        owner=$(meta_get "$d" "owner") || owner="?"
        items+=("$name" "@$owner")
    done

    if [[ ${#items[@]} -eq 0 ]]; then
        msg "РќРµС‚ С‚РёСЂ-Р»РёСЃС‚РѕРІ."
        return
    fi

    local choice
    choice=$(whiptail --title "РџСѓР±Р»РёС‡РЅС‹Рµ С‚РёСЂ-Р»РёСЃС‚С‹" --menu "\nР’С‹Р±РµСЂРёС‚Рµ С‚РёСЂ-Р»РёСЃС‚:" 20 70 10 \
        "${items[@]}" 3>&1 1>&2 2>&3) || return

    view_tierlist "$TIERLISTS_DIR/$choice"
}

### view tierlist ###

view_tierlist() {
    local tl_dir="$1"
    local tl_name
    tl_name=$(basename "$tl_dir")

    while true; do
        if [[ ! -d "$tl_dir" ]]; then
            return
        fi

        local owner
        owner=$(meta_get "$tl_dir" "owner") || owner="?"

        local menu_items=()
        local -a tag_map=()
        local n=1

        if is_owner "$tl_dir"; then
            tag_map[$n]="rename_tl"
            menu_items+=("$n" "  РџРµСЂРµРёРјРµРЅРѕРІР°С‚СЊ С‚РёСЂ-Р»РёСЃС‚")
            ((n++))
            tag_map[$n]="delete_tl"
            menu_items+=("$n" "  РЈРґР°Р»РёС‚СЊ С‚РёСЂ-Р»РёСЃС‚")
            ((n++))
        fi

        if ! is_owner "$tl_dir" && ! is_collaborator "$tl_dir"; then
            tag_map[$n]="join"
            menu_items+=("$n" "  РџСЂРёСЃРѕРµРґРёРЅРёС‚СЊСЃСЏ")
            ((n++))
        fi
        if ! is_owner "$tl_dir" && is_collaborator "$tl_dir"; then
            tag_map[$n]="leave"
            menu_items+=("$n" "  РџРѕРєРёРЅСѓС‚СЊ")
            ((n++))
        fi

        if can_edit "$tl_dir"; then
            tag_map[$n]="add_tier"
            menu_items+=("$n" "  Р”РѕР±Р°РІРёС‚СЊ С‚РёСЂ")
            ((n++))
            tag_map[$n]="del_tier"
            menu_items+=("$n" "  РЈРґР°Р»РёС‚СЊ С‚РёСЂ")
            ((n++))
            tag_map[$n]="add_item"
            menu_items+=("$n" "  Р”РѕР±Р°РІРёС‚СЊ СЌР»РµРјРµРЅС‚")
            ((n++))
        fi

        tag_map[$n]="header"
        menu_items+=("$n" "======================")
        ((n++))

        local tier_dirs=()
        while IFS= read -r -d '' td; do
            tier_dirs+=("$td")
        done < <(find "$tl_dir" -type d -name 'tier_*' -print0 2>/dev/null | sort -z)

        for td in "${tier_dirs[@]}"; do
            local rel="${td#$tl_dir/}"
            local tier_label
            tier_label=$(basename "$td" | sed 's/tier_//' | tr '[:lower:]' '[:upper:]')

            tag_map[$n]="header"
            menu_items+=("$n" "======= $tier_label =======")
            ((n++))

            for f in "$td"/*.txt; do
                [[ -f "$f" ]] || continue
                local fname
                fname=$(basename "$f")
                local fname_no_ext="${fname%.txt}"

                if is_restricted "$tl_dir" "$fname" && ! is_owner "$tl_dir"; then
                    tag_map[$n]="item:$rel/$fname"
                    menu_items+=("$n" "  [LOCKED] $fname_no_ext")
                else
                    local preview
                    preview=$(cat "$f" 2>/dev/null | tr '\n' ' ' | cut -c1-50)
                    tag_map[$n]="item:$rel/$fname"
                    menu_items+=("$n" "  $fname_no_ext: $preview")
                fi
                ((n++))
            done
        done

        local choice
        choice=$(whiptail --title "$tl_name [@$owner]" \
            --menu "" 0 0 0 \
            "${menu_items[@]}" 3>&1 1>&2 2>&3) || return

        local action="${tag_map[$choice]}"

        [[ "$action" == "header" ]] && continue

        if [[ "$action" == "item:"* ]]; then
            local item_path="${action#item:}"
            view_item "$tl_dir" "$item_path"
            continue
        fi

        case "$action" in
            rename_tl)
                local new_name
                new_name=$(input "РќРѕРІРѕРµ РЅР°Р·РІР°РЅРёРµ:" "$tl_name") || continue
                new_name=$(echo "$new_name" | sed 's/[^a-zA-Z0-9_-]//g')
                if [[ -z "$new_name" || "$new_name" == "$tl_name" ]]; then
                    continue
                fi
                mv "$TIERLISTS_DIR/$tl_name" "$TIERLISTS_DIR/$new_name"
                tl_dir="$TIERLISTS_DIR/$new_name"
                tl_name="$new_name"
                ;;
            delete_tl)
                if yesno "РЈРґР°Р»РёС‚СЊ С‚РёСЂ-Р»РёСЃС‚ '$tl_name' Рё РІСЃС‘ РµРіРѕ СЃРѕРґРµСЂР¶РёРјРѕРµ?"; then
                    rm -rf "${TIERLISTS_DIR:?}/$tl_name"
                    msg "РўРёСЂ-Р»РёСЃС‚ '$tl_name' СѓРґР°Р»С‘РЅ."
                    return
                fi
                ;;
            join)
                join_tierlist_by_name "$tl_name"
                local new_name="${tl_name}__with__${CURRENT_USER}"
                if [[ -d "$TIERLISTS_DIR/$new_name" ]]; then
                    tl_dir="$TIERLISTS_DIR/$new_name"
                    tl_name="$new_name"
                fi
                ;;
            leave)
                leave_tierlist_by_name "$tl_name"
                return ;;
            add_tier) add_tier "$tl_dir" ;;
            del_tier) del_tier "$tl_dir" ;;
            add_item) add_item "$tl_dir" ;;
        esac
    done
}

### view item ###

view_item() {
    local tl_dir="$1"
    local item_path="$2"
    local item_file="$tl_dir/$item_path"
    local item_fname
    item_fname=$(basename "$item_file")
    local item_name="${item_fname%.txt}"
    local item_tier_dir
    item_tier_dir=$(dirname "$item_file")

    while true; do
        [[ -f "$item_file" ]] || return

        if ! can_read_file "$tl_dir" "$item_fname"; then
            msg "[LOCKED] $item_name\n\nР”РѕСЃС‚СѓРї РѕРіСЂР°РЅРёС‡РµРЅ РІР»Р°РґРµР»СЊС†РµРј С‚РёСЂ-Р»РёСЃС‚Р°."
            return
        fi

        local content
        content=$(cat "$item_file" 2>/dev/null)

        local menu_items=()
        local -a tag_map=()
        local n=1

        if can_edit "$tl_dir"; then
            if ! is_restricted "$tl_dir" "$item_fname" || is_owner "$tl_dir"; then
                tag_map[$n]="edit"
                menu_items+=("$n" "  Р РµРґР°РєС‚РёСЂРѕРІР°С‚СЊ")
                ((n++))
                tag_map[$n]="rename"
                menu_items+=("$n" "  РџРµСЂРµРёРјРµРЅРѕРІР°С‚СЊ")
                ((n++))
                tag_map[$n]="move"
                menu_items+=("$n" "  РџРµСЂРµРјРµСЃС‚РёС‚СЊ РІ РґСЂСѓРіРѕР№ С‚РёСЂ")
                ((n++))
                tag_map[$n]="delete"
                menu_items+=("$n" "  РЈРґР°Р»РёС‚СЊ")
                ((n++))
            fi
        fi

        tag_map[$n]="back"
        menu_items+=("$n" "  РќР°Р·Р°Рґ")

        local choice
        choice=$(whiptail --title "$item_name" \
            --menu "$content" 0 0 0 \
            "${menu_items[@]}" 3>&1 1>&2 2>&3) || return

        local action="${tag_map[$choice]}"

        case "$action" in
            edit)
                local new_content
                new_content=$(input "РќРѕРІРѕРµ РѕРїРёСЃР°РЅРёРµ:" "$content") || continue
                echo "$new_content" > "$item_file"
                msg "Р­Р»РµРјРµРЅС‚ РѕР±РЅРѕРІР»С‘РЅ."
                ;;
            rename)
                local new_name
                new_name=$(input "РќРѕРІРѕРµ РёРјСЏ (Р±РµР· .txt):" "$item_name") || continue
                new_name=$(echo "$new_name" | sed 's/[^a-zA-Z0-9_-]//g')
                if [[ -z "$new_name" || "$new_name" == "$item_name" ]]; then
                    continue
                fi
                mv "$item_file" "$item_tier_dir/${new_name}.txt"
                item_fname="${new_name}.txt"
                item_name="$new_name"
                item_file="$item_tier_dir/$item_fname"
                item_path="${item_tier_dir#$tl_dir/}/$item_fname"
                msg "Р­Р»РµРјРµРЅС‚ РїРµСЂРµРёРјРµРЅРѕРІР°РЅ."
                ;;
            move)
                local dst_tier
                dst_tier=$(select_tier "$tl_dir") || continue
                local src_rel="${item_tier_dir#$tl_dir/}"
                if [[ "$src_rel" == "$dst_tier" ]]; then
                    msg "РСЃС‚РѕС‡РЅРёРє Рё РЅР°Р·РЅР°С‡РµРЅРёРµ СЃРѕРІРїР°РґР°СЋС‚."
                    continue
                fi
                mv "$item_file" "$tl_dir/$dst_tier/$item_fname"
                item_tier_dir="$tl_dir/$dst_tier"
                item_file="$item_tier_dir/$item_fname"
                item_path="$dst_tier/$item_fname"
                msg "Р­Р»РµРјРµРЅС‚ РїРµСЂРµРјРµС‰С‘РЅ РІ $dst_tier."
                ;;
            delete)
                if yesno "РЈРґР°Р»РёС‚СЊ СЌР»РµРјРµРЅС‚ '$item_name'?"; then
                    rm -f "$item_file"
                    msg "Р­Р»РµРјРµРЅС‚ СѓРґР°Р»С‘РЅ."
                    return
                fi
                ;;
            back) return ;;
        esac
    done
}

### tier operations ###

select_tier() {
    local tl_dir="$1"
    local items=()
    while IFS= read -r -d '' tier_dir; do
        local rel="${tier_dir#$tl_dir/}"
        local count
        count=$(find "$tier_dir" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l)
        items+=("$rel" "$count СЌР»РµРјРµРЅС‚РѕРІ")
    done < <(find "$tl_dir" -type d -name 'tier_*' -print0 2>/dev/null | sort -z)

    if [[ ${#items[@]} -eq 0 ]]; then
        msg "РќРµС‚ С‚РёСЂРѕРІ."
        return 1
    fi

    whiptail --title "Р’С‹Р±РµСЂРёС‚Рµ С‚РёСЂ" --menu "" 18 70 10 \
        "${items[@]}" 3>&1 1>&2 2>&3
}



add_tier() {
    local tl_dir="$1"
    local name
    name=$(input "РРјСЏ РЅРѕРІРѕРіРѕ С‚РёСЂР° (РЅР°РїСЂРёРјРµСЂ: tier_s, tier_a):" "tier_") || return
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_]//g')

    if [[ -z "$name" ]]; then
        msg "РРјСЏ РЅРµ РјРѕР¶РµС‚ Р±С‹С‚СЊ РїСѓСЃС‚С‹Рј."
        return
    fi

    if [[ -d "$tl_dir/$name" ]]; then
        msg "РўРёСЂ '$name' СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚."
        return
    fi

    mkdir -p "$tl_dir/$name"
    msg "РўРёСЂ '$name' СЃРѕР·РґР°РЅ."
}

del_tier() {
    local tl_dir="$1"
    local tier
    tier=$(select_tier "$tl_dir") || return

    if yesno "РЈРґР°Р»РёС‚СЊ С‚РёСЂ '$tier' Рё РІСЃРµ РµРіРѕ СЌР»РµРјРµРЅС‚С‹?"; then
        rm -rf "${tl_dir:?}/$tier"
        msg "РўРёСЂ '$tier' СѓРґР°Р»С‘РЅ."
    fi
}

### item operations ###


add_item() {
    local tl_dir="$1"
    local tier
    tier=$(select_tier "$tl_dir") || return

    local name
    name=$(input "РРјСЏ СЌР»РµРјРµРЅС‚Р° (snake_case, Р±РµР· .txt):" "") || return
    name=$(echo "$name" | sed 's/[^a-zA-Z0-9_-]//g')

    if [[ -z "$name" ]]; then
        msg "РРјСЏ РЅРµ РјРѕР¶РµС‚ Р±С‹С‚СЊ РїСѓСЃС‚С‹Рј."
        return
    fi

    local fname="${name}.txt"
    if [[ -f "$tl_dir/$tier/$fname" ]]; then
        msg "Р­Р»РµРјРµРЅС‚ '$name' СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚ РІ СЌС‚РѕРј С‚РёСЂРµ."
        return
    fi

    local content
    content=$(input "РћРїРёСЃР°РЅРёРµ СЌР»РµРјРµРЅС‚Р°:" "") || return

    echo "$content" > "$tl_dir/$tier/$fname"
    msg "Р­Р»РµРјРµРЅС‚ '$name' РґРѕР±Р°РІР»РµРЅ РІ $tier."
}


### tierlist management ###

create_tierlist() {
    local name
    name=$(input "РќР°Р·РІР°РЅРёРµ РЅРѕРІРѕРіРѕ С‚РёСЂ-Р»РёСЃС‚Р° (snake_case):" "") || return
    name=$(echo "$name" | sed 's/[^a-zA-Z0-9_-]//g')

    if [[ -z "$name" ]]; then
        msg "РќР°Р·РІР°РЅРёРµ РЅРµ РјРѕР¶РµС‚ Р±С‹С‚СЊ РїСѓСЃС‚С‹Рј."
        return
    fi

    if [[ -d "$TIERLISTS_DIR/$name" ]]; then
        msg "РўРёСЂ-Р»РёСЃС‚ '$name' СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚."
        return
    fi

    mkdir -p "$TIERLISTS_DIR/$name"
    cat > "$TIERLISTS_DIR/$name/.meta" << EOF
owner=$CURRENT_USER
restricted=
collaborators=
EOF

    msg "РўРёСЂ-Р»РёСЃС‚ '$name' СЃРѕР·РґР°РЅ."
}


### join / leave ###

join_tierlist_by_name() {
    local tl_name="$1"
    local new_name="${tl_name}__with__${CURRENT_USER}"

    mv "$TIERLISTS_DIR/$tl_name" "$TIERLISTS_DIR/$new_name"

    local collabs
    collabs=$(meta_get "$TIERLISTS_DIR/$new_name" "collaborators") || collabs=""
    if [[ -z "$collabs" ]]; then
        meta_set "$TIERLISTS_DIR/$new_name" "collaborators" "$CURRENT_USER"
    else
        meta_set "$TIERLISTS_DIR/$new_name" "collaborators" "${collabs},${CURRENT_USER}"
    fi

    msg "Р’С‹ РїСЂРёСЃРѕРµРґРёРЅРёР»РёСЃСЊ Рє С‚РёСЂ-Р»РёСЃС‚Сѓ."
}

leave_tierlist_by_name() {
    local tl_name="$1"

    local collabs
    collabs=$(meta_get "$TIERLISTS_DIR/$tl_name" "collaborators") || collabs=""
    local new_collabs=""
    local IFS=','
    for c in $collabs; do
        [[ "$c" == "$CURRENT_USER" ]] && continue
        if [[ -z "$new_collabs" ]]; then
            new_collabs="$c"
        else
            new_collabs="${new_collabs},$c"
        fi
    done
    unset IFS
    meta_set "$TIERLISTS_DIR/$tl_name" "collaborators" "$new_collabs"

    local original="${tl_name%__with__${CURRENT_USER}}"
    if [[ "$original" != "$tl_name" ]]; then
        mv "$TIERLISTS_DIR/$tl_name" "$TIERLISTS_DIR/$original"
    fi

    msg "Р’С‹ РїРѕРєРёРЅСѓР»Рё С‚РёСЂ-Р»РёСЃС‚."
}

### main menu ###

main_menu() {
    while true; do
        local choice
        choice=$(whiptail --title "$TITLE [$CURRENT_USER]" \
            --menu "\nР”РѕР±СЂРѕ РїРѕР¶Р°Р»РѕРІР°С‚СЊ! Р’С‹Р±РµСЂРёС‚Рµ РґРµР№СЃС‚РІРёРµ:\n" 16 65 4 \
            "1" "РџСѓР±Р»РёС‡РЅС‹Рµ С‚РёСЂ-Р»РёСЃС‚С‹" \
            "2" "РњРѕРё С‚РёСЂ-Р»РёСЃС‚С‹" \
            "3" "РЎРѕР·РґР°С‚СЊ С‚РёСЂ-Р»РёСЃС‚" \
            "q" "Р’С‹С…РѕРґ" \
            3>&1 1>&2 2>&3) || break

        case "$choice" in
            1) list_all_tierlists ;;
            2) list_my_tierlists ;;
            3) create_tierlist ;;
            q) break ;;
        esac
    done
}

### entry point ###

do_login
main_menu