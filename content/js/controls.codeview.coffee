class window.Controls.codeview extends window.Control
    createDom: () ->
        """
            <div class="control control-inset codeview"> 
            </div>
        """

    setupDom: (dom) ->
        super(dom)
        @cm = letsencrypt @dom,
            value: @properties.value
            mode: @properties.mode
            lineNumbers: true
            matchBrackets: true
        $(@dom).children().css(
            width:  @_int_to_px(@properties.width)
        )
        $(@dom).find('.letsencrypt-scroll').css(
            height: @_int_to_px(@properties.height)
        )
        cm = @cm
        jQuery(@dom).find('.letsencrypt').resizable resize: () ->
            cm.setSize $(this).width(), $(this).height()
            cm.refresh()
            
        setTimeout @cm.refresh, 1

    onBroadcast: (msg) ->
        if msg == 'visible'
            setTimeout @cm.refresh, 1

    detectUpdates: () ->
        r = {}
        value = @cm.getValue()
        if value != @properties.value
            r.value = value
        return r
