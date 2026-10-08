return function(arg)
    local candidates = {}
    for _, player in pairs(GetActivePlayerList()) do
        if player ~= nil and player:IsBot() and player:IsAlive() and player:GetTeamNumber() == 3 then
            candidates[#candidates + 1] = player
        end
    end
    if #candidates == 0 then return end
    local zombie = candidates[math.random(#candidates)]
    local classID = zombie:GetClass()
    local characterInfo = CSO2ResourceManager:GetCharacterDataInfo(classID)
    local iGender = characterInfo.m_iGender
    if iGender == 2 then
        ChangeZombie(zombie, HOSTZOMBIE_F, HOST, 0)
    else
        ChangeZombie(zombie, HOSTZOMBIE, HOST, 0)
    end
    Gamestate = 1
end