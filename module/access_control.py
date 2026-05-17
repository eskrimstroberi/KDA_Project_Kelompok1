def login_role():

    print("\n" + "=" * 50)
    print("SECURE HEALTH DATA SYSTEM")
    print("=" * 50)

    print("\nLogin sebagai:")
    print("1. Admin")
    print("2. Doctor")
    print("3. Guest")

    choice = input(
        "\nPilih role (1/2/3): "
    ).strip()

    role_map = {
        "1": "admin",
        "2": "doctor",
        "3": "guest"
    }

    role = role_map.get(
        choice,
        "guest"
    )

    print(
        f"\nRole aktif : {role}"
    )

    return role