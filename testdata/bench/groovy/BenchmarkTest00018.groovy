class AdminController {
    def deleteItem() {
        def itemId = params.itemId?.toLong()
        if (itemId) {
            Item.get(itemId)?.delete()
        }
        redirect(action: "list")
    }
}
